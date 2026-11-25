//! The gateway's OAuth 2.1 authorization server and its token check (spec 18.4, points 6 to 10).
//! This is the only part of tear-mesh that faces the internet. Everything lives in gateway.db, read on
//! every request, so the commands (grants, revoke, passphrase) take effect at the very next one.

// route and check hand back whole requests and responses, which is what their callers use.
#![allow(clippy::result_large_err)]

use std::fmt::Display;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::body::Body;
use hyper::http::{self, HeaderMap, Method, header};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

type Response = http::Response<Full<Bytes>>;

const BODY_CAP: usize = 64 * 1024;
const MAX_GRANTS: i64 = 20;
const MAX_REDIRECTS: usize = 5;
const MAX_REDIRECT_LEN: usize = 255;
// Five long redirect URIs and a long name in wide characters would pass 2,000 bytes; real clients send one or two short ones.
const MAX_CLIENT_ID: usize = 1500;
const PRM: &str = "/.well-known/oauth-protected-resource";
const CLAUDE_CALLBACKS: [&str; 2] = ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"];
// No form-action: Chrome applies it to the redirect after the form too, which would block the return to claude.ai.
const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'";

pub struct Config {
    pub url: String,
    pub dir: PathBuf,
    pub access_ttl: Duration,
    pub refresh_ttl: Duration,
    pub code_ttl: Duration,
    /// A sign-in request body must arrive within this (408): a trickling body would hold a connection slot.
    pub body_timeout: Duration,
    /// A replaced refresh token used again within this is only refused: Claude's workers refresh at the same moment.
    pub reuse_grace: Duration,
}

impl Config {
    pub fn new(url: &str, dir: &Path) -> anyhow::Result<Config> {
        split_url(url)?;
        Ok(Config {
            url: url.to_string(),
            dir: dir.to_path_buf(),
            access_ttl: Duration::from_secs(3600),
            refresh_ttl: Duration::from_secs(60 * 24 * 3600),
            code_ttl: Duration::from_secs(60),
            body_timeout: Duration::from_secs(5),
            reuse_grace: Duration::from_secs(60),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub id: String,
    pub client: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct GrantInfo {
    pub id: String,
    pub client: String,
    pub created_ms: u64,
    pub last_used_ms: u64,
    pub calls: u64,
}

/// For the audit log. Never holds a token, a code or the passphrase.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Register { client: String },
    ConsentOk { grant: String, client: String },
    ConsentWrong { client: String },
    Token { grant: String },
    Refresh { grant: String },
    Refused { why: String },
    RevokedUsed { grant: String },
    /// A replaced refresh token used again, after the grace: someone holds a copy; the sign-in is ended.
    ReplacedUsed { grant: String },
}

#[derive(Clone)]
pub struct OAuth(Arc<Inner>);

struct Inner {
    cfg: Config,
    origin: String,
    // The connector URL's path without a trailing slash: the protected resource metadata is also served under it.
    suffix: String,
    // shortcut: one connection behind a std Mutex, so SQLite work blocks a runtime thread for its few
    // milliseconds; move to spawn_blocking if the gateway ever serves enough sign-ins for that to matter.
    db: Mutex<Connection>,
    // Seals client ids; made on first open, it never leaves gateway.db.
    seal: [u8; 32],
    audit: Arc<dyn Fn(&Event) + Send + Sync>,
}

struct Ask {
    client: String,
    name: String,
    redirect: String,
    state: Option<String>,
    challenge: String,
    resource: Option<String>,
}

impl OAuth {
    pub fn open(cfg: Config, audit: Arc<dyn Fn(&Event) + Send + Sync>) -> anyhow::Result<OAuth> {
        let (origin, path) = split_url(&cfg.url)?;
        let db = open_db(&cfg.dir)?;
        db.execute("INSERT OR IGNORE INTO seal (id, key) VALUES (1, ?1)", [random::<32>().as_slice()])?;
        let key: Vec<u8> = db.query_row("SELECT key FROM seal WHERE id = 1", [], |r| r.get(0))?;
        let seal: [u8; 32] = key.try_into().map_err(|_| anyhow::anyhow!("the stored client key is damaged"))?;
        let suffix = path.trim_end_matches('/').to_string();
        Ok(OAuth(Arc::new(Inner { cfg, origin, suffix, db: Mutex::new(db), seal, audit })))
    }

    /// Answers the OAuth paths. Any other path: the request is handed back untouched in Err.
    pub async fn route<B>(&self, req: http::Request<B>) -> Result<Response, http::Request<B>>
    where
        B: Body + Send,
        B::Data: Send,
        B::Error: Display,
    {
        let path = req.uri().path();
        let well_known = path == PRM || path == format!("{PRM}{}", self.0.suffix);
        let known = ["/.well-known/oauth-authorization-server", "/register", "/authorize", "/token"];
        if !well_known && !known.contains(&path) {
            return Err(req);
        }
        let path = path.to_string();
        let method = req.method().clone();
        let answer = match (path.as_str(), method) {
            (_, Method::GET) if well_known => Ok(self.resource_metadata()),
            ("/.well-known/oauth-authorization-server", Method::GET) => Ok(self.server_metadata()),
            ("/authorize", Method::GET) => self.sign_in_page(req.uri().query().unwrap_or("")),
            (p @ ("/register" | "/authorize" | "/token"), Method::POST) => match tokio::time::timeout(self.0.cfg.body_timeout, read_body(req.into_body())).await {
                Err(_) => Ok(reply(408, "text/plain", "the request body took too long", &[])),
                Ok(Err(r)) => Ok(r),
                Ok(Ok(body)) if p == "/register" => self.register(&body),
                Ok(Ok(body)) if p == "/authorize" => self.consent(&body),
                Ok(Ok(body)) => self.token(&body),
            },
            _ => Ok(reply(405, "text/plain", "method not allowed", &[])),
        };
        Ok(answer.unwrap_or_else(|e| {
            tracing::warn!("gateway sign-in failed inside: {e:#}");
            reply(500, "text/plain", "the gateway could not answer", &[])
        }))
    }

    /// Checks the Authorization header of an MCP request and counts the call. Err is the complete response.
    /// Only the header is read: a token in the URL is never looked at.
    pub fn check(&self, headers: &HeaderMap) -> Result<Grant, Response> {
        let mut values = headers.get_all(header::AUTHORIZATION).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(self.unauthorized(false));
        };
        let token = value
            .to_str()
            .ok()
            .and_then(|s| s.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
            .map(|(_, t)| t.trim())
            .filter(|t| !t.is_empty());
        let Some(token) = token else {
            self.audit(Event::Refused { why: "the Authorization header is not a bearer token".into() });
            return Err(self.unauthorized(true));
        };
        self.check_token(token).unwrap_or_else(|e| {
            tracing::warn!("gateway token check failed inside: {e:#}");
            Err(reply(500, "text/plain", "the gateway could not check the token", &[]))
        })
    }

    fn check_token(&self, token: &str) -> anyhow::Result<Result<Grant, Response>> {
        let db = self.db();
        let now = now_ms();
        // Looked up by hash: an index lookup on a hash leaks nothing about the token it came from.
        let row: Option<(String, i64)> = db
            .query_row("SELECT grant_id, expires_ms FROM tokens WHERE hash = ?1 AND kind = 'access'", [digest(token)], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let Some((grant, expires)) = row else {
            self.audit(Event::Refused { why: "unknown access token".into() });
            return Ok(Err(self.unauthorized(true)));
        };
        if expires <= now {
            self.audit(Event::Refused { why: "expired access token".into() });
            return Ok(Err(self.unauthorized(true)));
        }
        let name: Option<String> = db
            .query_row(
                "UPDATE grants SET calls = calls + 1, last_used_ms = ?1 WHERE id = ?2 RETURNING name",
                params![now, grant],
                |r| r.get(0),
            )
            .optional()?;
        let Some(client) = name else {
            self.audit(Event::RevokedUsed { grant });
            return Ok(Err(self.unauthorized(true)));
        };
        Ok(Ok(Grant { id: grant, client }))
    }

    fn unauthorized(&self, bad_token: bool) -> Response {
        let pointer = format!("resource_metadata=\"{}{PRM}{}\"", self.0.origin, self.0.suffix);
        let value = if bad_token { format!("Bearer error=\"invalid_token\", {pointer}") } else { format!("Bearer {pointer}") };
        let body = json!({"error": "invalid_token", "error_description": "sign in to the gateway first"}).to_string();
        reply(401, "application/json", body, &[(header::WWW_AUTHENTICATE.as_str(), &value)])
    }

    fn resource_metadata(&self) -> Response {
        json_reply(200, json!({
            "resource": self.0.cfg.url,
            "authorization_servers": [self.0.origin],
            "bearer_methods_supported": ["header"],
            "resource_name": "tear-mesh gateway",
        }))
    }

    fn server_metadata(&self) -> Response {
        let o = &self.0.origin;
        // No client_id_metadata_document_supported (limit/gateway-no-cimd): Claude then registers dynamically.
        // offline_access is listed because Claude asks for refresh tokens only when it is.
        json_reply(200, json!({
            "issuer": o,
            "authorization_endpoint": format!("{o}/authorize"),
            "token_endpoint": format!("{o}/token"),
            "registration_endpoint": format!("{o}/register"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["offline_access"],
        }))
    }

    fn register(&self, body: &[u8]) -> anyhow::Result<Response> {
        let Ok(serde_json::Value::Object(meta)) = serde_json::from_slice(body) else {
            return Ok(self.refuse(400, "invalid_client_metadata", "the registration is not a JSON object"));
        };
        let uris: Option<Vec<String>> = meta
            .get("redirect_uris")
            .and_then(|v| v.as_array())
            .and_then(|a| a.iter().map(|u| u.as_str().map(str::to_string)).collect());
        let uris = uris.unwrap_or_default();
        if uris.is_empty() || uris.len() > MAX_REDIRECTS || !uris.iter().all(|u| u.len() <= MAX_REDIRECT_LEN && redirect_allowed(u)) {
            return Ok(self.refuse(400, "invalid_redirect_uri", "only Claude's callback and http://localhost or http://127.0.0.1 may be registered"));
        }
        // Grant types, auth methods and any other field are ignored: every client is a public client with the same grants.
        let name = clean_name(meta.get("client_name").and_then(|v| v.as_str()).unwrap_or(""));
        // Nothing is stored: the id is the registration, so registering costs nothing and needs no limit.
        let id = self.seal(&name, &uris);
        if id.len() > MAX_CLIENT_ID {
            return Ok(self.refuse(400, "invalid_client_metadata", "the client name and redirect URIs are too long together"));
        }
        let now = now_ms();
        self.audit(Event::Register { client: name.clone() });
        Ok(json_reply(201, json!({
            "client_id": id,
            "client_id_issued_at": now / 1000,
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })))
    }

    fn sign_in_page(&self, query: &str) -> anyhow::Result<Response> {
        let form = Form::parse(query.as_bytes());
        let db = self.db();
        let now = now_ms();
        self.sweep(&db, now)?;
        let ask = match self.ask(form.as_ref()) {
            Ok(ask) => ask,
            Err(r) => return Ok(r),
        };
        if load_secret(&db)?.is_none() {
            return Ok(no_passphrase_page());
        }
        Ok(form_page(200, &ask, None))
    }

    fn consent(&self, body: &[u8]) -> anyhow::Result<Response> {
        let form = Form::parse(body);
        let db = self.db();
        let now = now_ms();
        self.sweep(&db, now)?;
        let ask = match self.ask(form.as_ref()) {
            Ok(ask) => ask,
            Err(r) => return Ok(r),
        };
        let Some((salt, stored)) = load_secret(&db)? else {
            return Ok(no_passphrase_page());
        };
        let phrase = form.as_ref().and_then(|f| f.get("passphrase")).unwrap_or("");
        // blake3::Hash compares in constant time. No lockout: six random words are beyond guessing, and a lock
        // would let anyone who knows the URL keep the owner out.
        if phrase_hash(&salt, phrase) != stored {
            self.audit(Event::ConsentWrong { client: ask.name.clone() });
            return Ok(form_page(403, &ask, Some("That passphrase is not right.")));
        }
        let grant = hex(&random::<8>());
        let code = B64.encode(random::<32>());
        db.execute(
            "INSERT INTO codes (hash, client, redirect, challenge, grant_id, expires_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![digest(&code), ask.client, ask.redirect, ask.challenge, grant, now + ms(self.0.cfg.code_ttl)],
        )?;
        self.audit(Event::ConsentOk { grant, client: ask.name });
        Ok(redirect_to(&ask.redirect, &[("code", &code)], ask.state.as_deref()))
    }

    /// Checks an authorization request, from the query (GET) or the form's hidden fields (POST).
    /// Problems with the client or the redirect URI are shown on the page; the others go back to the client.
    fn ask(&self, form: Option<&Form>) -> Result<Ask, Response> {
        let refused = |why: &str| Err(message_page(400, "Sign-in refused", why));
        let Some(f) = form else {
            return refused("The sign-in request is malformed: a parameter is badly encoded or appears twice.");
        };
        let Some(client) = f.get("client_id") else {
            return refused("The sign-in request names no app.");
        };
        let Some((name, redirects)) = self.unseal(client) else {
            return refused("This app is not registered with this gateway. Remove the connector in Claude and add it again.");
        };
        let redirect = match f.get("redirect_uri") {
            Some(r) => r.to_string(),
            None if redirects.len() == 1 => redirects[0].clone(),
            None => return refused("The sign-in request names no redirect URI."),
        };
        if !redirect_matches(&redirects, &redirect) {
            return refused("The redirect URI is not one this app registered.");
        }
        let state = f.get("state").map(str::to_string);
        if state.as_ref().is_some_and(|s| s.len() > 1024) {
            return Err(redirect_to(&redirect, &[("error", "invalid_request"), ("error_description", "state is too long")], None));
        }
        let fail = |error: &str, why: &str| Err(redirect_to(&redirect, &[("error", error), ("error_description", why)], state.as_deref()));
        if f.get("response_type") != Some("code") {
            return fail("unsupported_response_type", "only response_type=code is supported");
        }
        let challenge = f.get("code_challenge").unwrap_or("");
        if f.get("code_challenge_method") != Some("S256") || challenge.len() != 43 || !challenge.bytes().all(is_b64url) {
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required");
        }
        let resource = f.get("resource").map(str::to_string);
        if resource.as_ref().is_some_and(|r| !self.is_resource(r)) {
            return fail("invalid_target", "resource is not this gateway's URL");
        }
        Ok(Ask { client: client.to_string(), name, challenge: challenge.to_string(), redirect, state, resource })
    }

    fn token(&self, body: &[u8]) -> anyhow::Result<Response> {
        let Some(f) = Form::parse(body) else {
            return Ok(self.refuse(400, "invalid_request", "a parameter is badly encoded or appears twice"));
        };
        if f.get("resource").is_some_and(|r| !self.is_resource(r)) {
            return Ok(self.refuse(400, "invalid_target", "resource is not this gateway's URL"));
        }
        if f.get("client_id").is_some_and(|c| self.unseal(c).is_none()) {
            return Ok(self.refuse(401, "invalid_client", "the client id was not made by this gateway"));
        }
        let db = self.db();
        let now = now_ms();
        self.sweep(&db, now)?;
        match f.get("grant_type") {
            Some("authorization_code") => self.exchange(&db, &f, now),
            Some("refresh_token") => self.refresh(&db, &f, now),
            _ => Ok(self.refuse(400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")),
        }
    }

    fn exchange(&self, db: &Connection, f: &Form, now: i64) -> anyhow::Result<Response> {
        let (Some(code), Some(verifier), Some(client)) = (f.get("code"), f.get("code_verifier"), f.get("client_id")) else {
            return Ok(self.refuse(400, "invalid_request", "code, code_verifier and client_id are required"));
        };
        let row: Option<(String, String, String, String, i64, bool)> = db
            .query_row(
                "SELECT client, redirect, challenge, grant_id, expires_ms, used FROM codes WHERE hash = ?1",
                [digest(code)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
            )
            .optional()?;
        let Some((owner, redirect, challenge, grant, expires, used)) = row else {
            return Ok(self.refuse(400, "invalid_grant", "unknown or expired code"));
        };
        if used {
            // A code seen twice may have been stolen: end the sign-in it gave (OAuth 2.1, 4.1.3).
            db.execute("DELETE FROM grants WHERE id = ?1", [&grant])?;
            return Ok(self.refuse(400, "invalid_grant", "the code was already used; its sign-in is ended"));
        }
        // Any attempt uses the code up, a wrong one too.
        db.execute("UPDATE codes SET used = 1 WHERE hash = ?1", [digest(code)])?;
        if expires <= now {
            return Ok(self.refuse(400, "invalid_grant", "unknown or expired code"));
        }
        if client != owner || f.get("redirect_uri").is_some_and(|r| r != redirect) {
            return Ok(self.refuse(400, "invalid_grant", "the code was issued to another client or redirect URI"));
        }
        let good_verifier = (43..=128).contains(&verifier.len()) && verifier.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b));
        if !good_verifier || !same(B64.encode(Sha256::digest(verifier.as_bytes())).as_bytes(), challenge.as_bytes()) {
            return Ok(self.refuse(400, "invalid_grant", "the code verifier does not match"));
        }
        let Some((name, _)) = self.unseal(&owner) else {
            return Ok(self.refuse(401, "invalid_client", "the client id was not made by this gateway"));
        };
        if db.query_row("SELECT COUNT(*) FROM grants", [], |r| r.get::<_, i64>(0))? >= MAX_GRANTS {
            db.execute("DELETE FROM grants WHERE id = (SELECT id FROM grants ORDER BY last_used_ms, rowid LIMIT 1)", [])?;
        }
        db.execute(
            "INSERT INTO grants (id, client, name, created_ms, last_used_ms) VALUES (?1, ?2, ?3, ?4, ?4)",
            params![grant, owner, name, now],
        )?;
        let answer = self.issue(db, &grant, now)?;
        self.audit(Event::Token { grant });
        Ok(answer)
    }

    fn refresh(&self, db: &Connection, f: &Form, now: i64) -> anyhow::Result<Response> {
        let Some(token) = f.get("refresh_token") else {
            return Ok(self.refuse(400, "invalid_request", "refresh_token is required"));
        };
        let row: Option<(String, String, i64, Option<i64>)> = db
            .query_row(
                "SELECT grant_id, kind, expires_ms, replaced_ms FROM tokens WHERE hash = ?1 AND kind IN ('refresh', 'spent')",
                [digest(token)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        let Some((grant, kind, expires, replaced)) = row else {
            return Ok(self.refuse(400, "invalid_grant", "unknown or expired refresh token"));
        };
        if expires <= now {
            return Ok(self.refuse(400, "invalid_grant", "unknown or expired refresh token"));
        }
        let owner: Option<String> = db.query_row("SELECT client FROM grants WHERE id = ?1", [&grant], |r| r.get(0)).optional()?;
        let Some(owner) = owner else {
            self.audit(Event::RevokedUsed { grant });
            return Ok(oauth_error(400, "invalid_grant", "this sign-in has ended"));
        };
        if kind == "spent" && replaced.is_some_and(|t| now - t < ms(self.0.cfg.reuse_grace)) {
            // Another of Claude's workers refreshed at the same moment; it already holds the new tokens.
            return Ok(self.refuse(400, "invalid_grant", "the refresh token was just replaced"));
        }
        if kind == "spent" {
            // A replaced refresh token came back late: someone holds a copy. End the sign-in.
            db.execute("DELETE FROM grants WHERE id = ?1", [&grant])?;
            let why = format!("a replaced refresh token of sign-in {grant} was used; the sign-in is ended");
            self.audit(Event::ReplacedUsed { grant });
            return Ok(oauth_error(400, "invalid_grant", &why));
        }
        if f.get("client_id").is_some_and(|c| c != owner) {
            return Ok(self.refuse(400, "invalid_grant", "the refresh token was issued to another client"));
        }
        db.execute("UPDATE tokens SET kind = 'spent', replaced_ms = ?2 WHERE hash = ?1", params![digest(token), now])?;
        db.execute("UPDATE grants SET last_used_ms = ?1 WHERE id = ?2", params![now, grant])?;
        let answer = self.issue(db, &grant, now)?;
        self.audit(Event::Refresh { grant });
        Ok(answer)
    }

    /// New access and refresh tokens for a sign-in. Its earlier access tokens live on to their own expiry: a tool
    /// call in flight on another of Claude's workers must not fail because this one refreshed.
    fn issue(&self, db: &Connection, grant: &str, now: i64) -> anyhow::Result<Response> {
        let access = B64.encode(random::<32>());
        let refresh = B64.encode(random::<32>());
        let cfg = &self.0.cfg;
        db.execute(
            "INSERT INTO tokens (hash, grant_id, kind, expires_ms) VALUES (?1, ?3, 'access', ?4), (?2, ?3, 'refresh', ?5)",
            params![digest(&access), digest(&refresh), grant, now + ms(cfg.access_ttl), now + ms(cfg.refresh_ttl)],
        )?;
        Ok(json_reply(200, json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": cfg.access_ttl.as_secs().max(1),
            "refresh_token": refresh,
        })))
    }

    fn refuse(&self, status: u16, error: &str, why: &str) -> Response {
        self.audit(Event::Refused { why: why.to_string() });
        oauth_error(status, error, why)
    }

    /// Claude sends the canonical form of the URL (lowercase scheme and host, no default port, no trailing slash).
    fn is_resource(&self, r: &str) -> bool {
        canonical(r).is_some_and(|r| Some(r) == canonical(&self.0.cfg.url))
    }

    /// Forgets dead codes and tokens.
    fn sweep(&self, db: &Connection, now: i64) -> anyhow::Result<()> {
        db.execute("DELETE FROM codes WHERE expires_ms <= ?1", [now])?;
        db.execute("DELETE FROM tokens WHERE expires_ms <= ?1", [now])?;
        Ok(())
    }

    /// A client id is its registration: the name and redirect URIs, and a keyed hash only this gateway can make.
    fn seal(&self, name: &str, uris: &[String]) -> String {
        let payload = B64.encode(json!([name, uris]).to_string());
        let mac = blake3::keyed_hash(&self.0.seal, payload.as_bytes());
        format!("{payload}.{}", B64.encode(mac.as_bytes()))
    }

    fn unseal(&self, id: &str) -> Option<(String, Vec<String>)> {
        let (payload, mac) = id.split_once('.')?;
        let mac: [u8; 32] = B64.decode(mac).ok()?.try_into().ok()?;
        // blake3::Hash compares in constant time.
        if blake3::keyed_hash(&self.0.seal, payload.as_bytes()) != blake3::Hash::from_bytes(mac) {
            return None;
        }
        serde_json::from_slice(&B64.decode(payload).ok()?).ok()
    }

    fn db(&self) -> MutexGuard<'_, Connection> {
        self.0.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn audit(&self, e: Event) {
        (self.0.audit)(&e);
    }
}

pub fn set_passphrase(dir: &Path, phrase: &str) -> anyhow::Result<()> {
    if normalize(phrase).is_empty() {
        bail!("the passphrase is empty");
    }
    let salt = random::<32>();
    let hash = phrase_hash(&salt, phrase);
    open_db(dir)?.execute(
        "INSERT OR REPLACE INTO secret (id, salt, hash) VALUES (1, ?1, ?2)",
        params![salt.as_slice(), hash.as_bytes().as_slice()],
    )?;
    Ok(())
}

pub fn has_passphrase(dir: &Path) -> anyhow::Result<bool> {
    Ok(load_secret(&open_db(dir)?)?.is_some())
}

pub fn grants(dir: &Path) -> anyhow::Result<Vec<GrantInfo>> {
    let db = open_db(dir)?;
    let mut stmt = db.prepare("SELECT id, name, created_ms, last_used_ms, calls FROM grants ORDER BY created_ms, rowid")?;
    let rows = stmt.query_map([], |r| {
        Ok(GrantInfo {
            id: r.get(0)?,
            client: r.get(1)?,
            created_ms: r.get::<_, i64>(2)? as u64,
            last_used_ms: r.get::<_, i64>(3)? as u64,
            calls: r.get::<_, i64>(4)? as u64,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Ends one sign-in, or all with None. Returns how many were ended. Its tokens stop working at the next request.
pub fn revoke(dir: &Path, id: Option<&str>) -> anyhow::Result<usize> {
    let db = open_db(dir)?;
    Ok(match id {
        Some(id) => db.execute("DELETE FROM grants WHERE id = ?1", [id])?,
        None => {
            // Codes not yet redeemed are sign-ins under way: they end too.
            db.execute("DELETE FROM codes", [])?;
            db.execute("DELETE FROM grants", [])?
        }
    })
}

// Token rows outlive their sign-in until they expire, so a revoked sign-in that is used can be told from a
// forged token; they grant nothing once their grants row is gone. kind 'spent' is a replaced refresh token,
// kept to catch its reuse; replaced_ms says when.
const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS hits;
CREATE TABLE IF NOT EXISTS seal (id INTEGER PRIMARY KEY CHECK (id = 1), key BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, client TEXT NOT NULL, name TEXT NOT NULL,
    created_ms INTEGER NOT NULL, last_used_ms INTEGER NOT NULL, calls INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS tokens (hash BLOB PRIMARY KEY, grant_id TEXT NOT NULL, kind TEXT NOT NULL, expires_ms INTEGER NOT NULL,
    replaced_ms INTEGER);
CREATE TABLE IF NOT EXISTS codes (hash BLOB PRIMARY KEY, client TEXT NOT NULL, redirect TEXT NOT NULL, challenge TEXT NOT NULL,
    grant_id TEXT NOT NULL, expires_ms INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS secret (id INTEGER PRIMARY KEY CHECK (id = 1), salt BLOB NOT NULL, hash BLOB NOT NULL);
";

fn open_db(dir: &Path) -> anyhow::Result<Connection> {
    let path = dir.join("gateway.db");
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // SQLite gives the -wal and -shm files the database file's mode.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("cannot create {}", path.display()))?;
    }
    let db = Connection::open(&path).with_context(|| format!("cannot open {}", path.display()))?;
    // The commands open the same file while the gateway runs.
    db.busy_timeout(Duration::from_secs(5))?;
    db.execute_batch(SCHEMA).with_context(|| format!("cannot set up {}", path.display()))?;
    Ok(db)
}

fn load_secret(db: &Connection) -> anyhow::Result<Option<([u8; 32], blake3::Hash)>> {
    let row: Option<(Vec<u8>, Vec<u8>)> =
        db.query_row("SELECT salt, hash FROM secret WHERE id = 1", [], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let Some((salt, hash)) = row else { return Ok(None) };
    let salt: [u8; 32] = salt.try_into().map_err(|_| anyhow::anyhow!("the stored passphrase salt is damaged"))?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| anyhow::anyhow!("the stored passphrase hash is damaged"))?;
    Ok(Some((salt, blake3::Hash::from_bytes(hash))))
}

// The passphrase is six machine-made random words (about 77 bits), out of reach of guessing even at a fast hash's
// speed, so a salted fast hash is enough; a slow password hash is for phrases people choose.
fn phrase_hash(salt: &[u8; 32], phrase: &str) -> blake3::Hash {
    blake3::keyed_hash(salt, normalize(phrase).as_bytes())
}

/// Phones capitalise and space words as they like; the words carry the secret, not their spelling.
fn normalize(phrase: &str) -> String {
    phrase.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase).collect::<Vec<_>>().join(" ")
}

/// Splits a connector URL into its canonical origin and its path as written. Checks what Config::new promises.
fn split_url(url: &str) -> anyhow::Result<(String, String)> {
    if url.bytes().any(|b| !(0x21..=0x7e).contains(&b) || b"\"\\<>[]{}|^\x60".contains(&b)) {
        bail!("the gateway url {url:?} holds characters a plain URL cannot");
    }
    if url.contains('?') || url.contains('#') {
        bail!("the gateway url {url} must have no query and no fragment");
    }
    let lower = url.to_ascii_lowercase();
    let (scheme, rest) = match (lower.strip_prefix("https://"), lower.strip_prefix("http://")) {
        (Some(rest), _) => ("https", rest),
        (_, Some(rest)) => ("http", rest),
        _ => bail!("the gateway url {url} must start with https://"),
    };
    let end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..end];
    let path = &url[scheme.len() + 3 + end..];
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() || authority.contains('@') {
        bail!("the gateway url {url} needs a host name and no user name");
    }
    if port.is_some_and(|p| p.parse::<u16>().is_err()) {
        bail!("the gateway url {url} has a port that is not a number");
    }
    if scheme == "http" && host != "127.0.0.1" && host != "localhost" {
        bail!("the gateway url {url} must be https (http only on 127.0.0.1 or localhost, for tests)");
    }
    let default = if scheme == "https" { "443" } else { "80" };
    let origin = match port {
        Some(p) if p != default => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    };
    Ok((origin, path.to_string()))
}

fn canonical(url: &str) -> Option<String> {
    split_url(url).ok().map(|(origin, path)| format!("{origin}{}", path.trim_end_matches('/')))
}

fn redirect_allowed(uri: &str) -> bool {
    CLAUDE_CALLBACKS.contains(&uri) || loopback_key(uri).is_some()
}

/// Exact match, except that the port of a loopback redirect URI is ignored (RFC 8252 7.3).
fn redirect_matches(registered: &[String], uri: &str) -> bool {
    registered.iter().any(|r| r == uri || loopback_key(r).is_some_and(|k| Some(k) == loopback_key(uri)))
}

/// For http://localhost or http://127.0.0.1 on any port: the URI without its port. None for anything else.
fn loopback_key(uri: &str) -> Option<String> {
    if !uri.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~:/?@!$&'()*+,;=%".contains(&b)) {
        return None;
    }
    let rest = uri.strip_prefix("http://")?;
    let (host, rest) = ["localhost", "127.0.0.1"].into_iter().find_map(|h| rest.strip_prefix(h).map(|r| (h, r)))?;
    let rest = match rest.strip_prefix(':') {
        Some(r) => {
            let digits = r.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 || r[..digits].parse::<u16>().is_err() {
                return None;
            }
            &r[digits..]
        }
        None => rest,
    };
    // Whatever follows the host must start the path or the query: "localhost.evil.example" and "localhost@evil" stop here.
    if !(rest.is_empty() || rest.starts_with('/') || rest.starts_with('?')) {
        return None;
    }
    Some(format!("http://{host}{rest}"))
}

fn redirect_to(base: &str, pairs: &[(&str, &str)], state: Option<&str>) -> Response {
    let mut url = base.to_string();
    let mut sep = if base.contains('?') { '&' } else { '?' };
    for (k, v) in pairs.iter().copied().chain(state.map(|s| ("state", s))) {
        url.push(sep);
        url.push_str(&format!("{k}={}", pct(v)));
        sep = '&';
    }
    reply(302, "text/plain", "", &[("location", &url)])
}

async fn read_body<B>(body: B) -> Result<Vec<u8>, Response>
where
    B: Body,
    B::Error: Display,
{
    let too_big = || reply(413, "text/plain", "the request body is larger than 64 KiB", &[]);
    let mut body = std::pin::pin!(body);
    if body.size_hint().lower() > BODY_CAP as u64 {
        return Err(too_big());
    }
    let mut out = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| reply(400, "text/plain", format!("the request body could not be read: {e}"), &[]))?;
        if let Ok(mut data) = frame.into_data() {
            if out.len() + data.remaining() > BODY_CAP {
                return Err(too_big());
            }
            while data.has_remaining() {
                let chunk = data.chunk();
                out.extend_from_slice(chunk);
                let n = chunk.len();
                data.advance(n);
            }
        }
    }
    Ok(out)
}

/// An application/x-www-form-urlencoded body or query. None when a name appears twice (OAuth forbids it) or
/// the encoding is broken. Empty values count as absent.
struct Form(Vec<(String, String)>);

impl Form {
    fn parse(s: &[u8]) -> Option<Form> {
        let mut out: Vec<(String, String)> = Vec::new();
        for pair in s.split(|&b| b == b'&').filter(|p| !p.is_empty()) {
            let (k, v) = match pair.iter().position(|&b| b == b'=') {
                Some(i) => (&pair[..i], &pair[i + 1..]),
                None => (pair, &b""[..]),
            };
            let (k, v) = (unpct(k)?, unpct(v)?);
            if out.iter().any(|(seen, _)| *seen == k) {
                return None;
            }
            out.push((k, v));
        }
        Some(Form(out))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty())
    }
}

fn unpct(s: &[u8]) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = (*s.get(i + 1)? as char).to_digit(16)?;
                let lo = (*s.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8(out).ok()
}

fn pct(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The name a client gave itself, as shown on the page and by `gateway grants` on a terminal: no control or
/// direction-changing characters, 64 at most.
fn clean_name(name: &str) -> String {
    let bidi = |c: char| matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
    let name: String = name.chars().filter(|&c| !c.is_control() && !bidi(c)).take(64).collect();
    match name.trim() {
        "" => "an unnamed app".to_string(),
        n => n.to_string(),
    }
}

fn form_page(status: u16, ask: &Ask, error: Option<&str>) -> Response {
    // From the redirect URI that was checked: where the code really goes.
    let host = ask.redirect.split_once("://").map_or("", |(_, r)| r.split(['/', ':', '?']).next().unwrap_or(""));
    let back = match host {
        "localhost" | "127.0.0.1" => format!("{host}, an app on your own computer"),
        h => h.to_string(),
    };
    let mut hidden = String::new();
    let fields = [
        ("response_type", Some("code")),
        ("client_id", Some(ask.client.as_str())),
        ("redirect_uri", Some(ask.redirect.as_str())),
        ("state", ask.state.as_deref()),
        ("code_challenge", Some(ask.challenge.as_str())),
        ("code_challenge_method", Some("S256")),
        ("resource", ask.resource.as_deref()),
    ];
    for (name, value) in fields {
        if let Some(v) = value {
            hidden.push_str(&format!("<input type=\"hidden\" name=\"{name}\" value=\"{}\">\n", esc(v)));
        }
    }
    let error = error.map(|e| format!("<p class=\"err\" role=\"alert\">{}</p>\n", esc(e))).unwrap_or_default();
    let body = format!(
        "<h1>Sign in to tear-mesh</h1>
<p><strong>Anyone can send you a link to this page.</strong> Type the passphrase only if you yourself just added this connector in Claude.</p>
<p>The app calls itself: <strong>{name}</strong></p>
<p>After you sign in, your browser goes to: <strong>{back}</strong></p>
<p>Signing in lets the app read and send messages in your mesh through this gateway, until you revoke the sign-in.</p>
{error}<form method=\"post\" action=\"/authorize\">
{hidden}<label for=\"passphrase\">Gateway passphrase</label>
<input id=\"passphrase\" name=\"passphrase\" type=\"password\" autocomplete=\"current-password\" autocapitalize=\"none\" spellcheck=\"false\" required autofocus>
<button type=\"submit\">Sign in</button>
</form>",
        name = esc(&ask.name),
        back = esc(&back),
    );
    html(status, "Sign in to tear-mesh", &body, &[])
}

fn message_page(status: u16, title: &str, text: &str) -> Response {
    html(status, title, &format!("<h1>{}</h1>\n<p>{}</p>", esc(title), esc(text)), &[])
}

fn no_passphrase_page() -> Response {
    message_page(503, "Gateway not set up", "This gateway has no passphrase yet. Run tearmesh gateway setup on it first.")
}

fn html(status: u16, title: &str, body: &str, extra: &[(&str, &str)]) -> Response {
    let page = format!(
        "<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title>{}</title>
<style>body{{font:18px/1.5 system-ui,sans-serif;max-width:30rem;margin:2rem auto;padding:0 1rem}}
input,button{{font:inherit;width:100%;box-sizing:border-box;padding:.6rem;margin:.4rem 0}}.err{{color:#b00020}}</style>
</head><body>
{body}
</body></html>
",
        esc(title)
    );
    reply(status, "text/html; charset=utf-8", page, extra)
}

fn json_reply(status: u16, v: serde_json::Value) -> Response {
    reply(status, "application/json", v.to_string(), &[])
}

fn oauth_error(status: u16, error: &str, why: &str) -> Response {
    json_reply(status, json!({"error": error, "error_description": why}))
}

/// Every answer is uncacheable and unframeable, the JSON ones too: one rule is harder to get wrong.
fn reply(status: u16, content_type: &str, body: impl Into<Bytes>, extra: &[(&str, &str)]) -> Response {
    let mut b = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-frame-options", "DENY")
        .header("content-security-policy", CSP)
        .header("referrer-policy", "no-referrer");
    for (k, v) in extra {
        b = b.header(*k, *v);
    }
    b.body(Full::new(body.into())).unwrap_or_else(|_| {
        let mut r = http::Response::new(Full::new(Bytes::from_static(b"the gateway could not answer")));
        *r.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        r
    })
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // Without the system's random source no secret can be made; this fails only on a broken system.
    getrandom::fill(&mut b).expect("the system random source failed");
    b
}

fn digest(secret: &str) -> Vec<u8> {
    blake3::hash(secret.as_bytes()).as_bytes().to_vec()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

fn is_b64url(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn ms(d: Duration) -> i64 {
    d.as_millis().min(i64::MAX as u128) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://mesh.example.com/mcp";
    const PHRASE: &str = "amber bison cobalt dune ember fjord";
    const CLAUDE: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "a-verifier-of-fifty-characters-0123456789abcdefghi";

    struct T {
        dir: tempfile::TempDir,
        o: OAuth,
        events: Arc<Mutex<Vec<String>>>,
    }

    fn setup() -> T {
        setup_with(|_| {})
    }

    fn setup_with(f: impl FnOnce(&mut Config)) -> T {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::new(URL, dir.path()).unwrap();
        f(&mut cfg);
        set_passphrase(dir.path(), PHRASE).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let o = OAuth::open(cfg, Arc::new(move |e: &Event| sink.lock().unwrap().push(serde_json::to_string(e).unwrap()))).unwrap();
        T { dir, o, events }
    }

    fn request(method: &str, uri: &str, body: impl Into<Bytes>) -> http::Request<Full<Bytes>> {
        http::Request::builder().method(method).uri(uri).body(Full::new(body.into())).unwrap()
    }

    async fn call(o: &OAuth, method: &str, uri: &str, body: &str) -> (u16, HeaderMap, String) {
        let r = o.route(request(method, uri, body.to_string())).await.unwrap_or_else(|_| panic!("{uri} not answered"));
        let status = r.status().as_u16();
        let headers = r.headers().clone();
        let body = r.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn challenge(verifier: &str) -> String {
        B64.encode(Sha256::digest(verifier.as_bytes()))
    }

    async fn register(o: &OAuth, redirect: &str) -> String {
        let body = json!({"client_name": "Claude", "redirect_uris": [redirect]}).to_string();
        let (status, _, body) = call(o, "POST", "/register", &body).await;
        assert_eq!(status, 201, "{body}");
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["client_id"].as_str().unwrap().to_string()
    }

    fn ask(client: &str, redirect: &str) -> String {
        format!(
            "response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256&state=st%20ate&resource={}",
            pct(client),
            pct(redirect),
            challenge(VERIFIER),
            pct(URL)
        )
    }

    fn query_of(location: &str) -> Form {
        Form::parse(location.split_once('?').unwrap().1.as_bytes()).unwrap()
    }

    async fn sign_in(o: &OAuth, client: &str, redirect: &str) -> String {
        let (status, headers, body) = call(o, "POST", "/authorize", &format!("{}&passphrase={}", ask(client, redirect), pct(PHRASE))).await;
        assert_eq!(status, 302, "{body}");
        let location = headers["location"].to_str().unwrap();
        assert!(location.starts_with(&format!("{redirect}?code=")), "{location}");
        let q = query_of(location);
        assert_eq!(q.get("state"), Some("st ate"));
        q.get("code").unwrap().to_string()
    }

    async fn exchange(o: &OAuth, client: &str, code: &str, verifier: &str) -> (u16, serde_json::Value) {
        let body = format!("grant_type=authorization_code&code={}&code_verifier={verifier}&client_id={}&redirect_uri={}&resource={}", pct(code), pct(client), pct(CLAUDE), pct(URL));
        let (status, headers, body) = call(o, "POST", "/token", &body).await;
        assert_eq!(headers["cache-control"], "no-store");
        (status, serde_json::from_str(&body).unwrap())
    }

    async fn tokens(o: &OAuth, client: &str, code: &str) -> (String, String) {
        let (status, v) = exchange(o, client, code, VERIFIER).await;
        assert_eq!(status, 200, "{v}");
        (v["access_token"].as_str().unwrap().to_string(), v["refresh_token"].as_str().unwrap().to_string())
    }

    async fn refresh(o: &OAuth, rt: &str) -> (u16, serde_json::Value) {
        let (status, _, body) = call(o, "POST", "/token", &format!("grant_type=refresh_token&refresh_token={}&resource={}", pct(rt), pct(URL))).await;
        (status, serde_json::from_str(&body).unwrap())
    }

    async fn signed_in(o: &OAuth) -> (String, String, String) {
        let client = register(o, CLAUDE).await;
        let code = sign_in(o, &client, CLAUDE).await;
        let (a, r) = tokens(o, &client, &code).await;
        (client, a, r)
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        h
    }

    fn side_db(t: &T) -> Connection {
        Connection::open(t.dir.path().join("gateway.db")).unwrap()
    }

    #[tokio::test]
    async fn whole_flow() {
        let t = setup();
        let o = &t.o;
        let body = json!({"client_name": "<b>Claude</b>", "redirect_uris": [CLAUDE]}).to_string();
        let (status, _, reg) = call(o, "POST", "/register", &body).await;
        assert_eq!(status, 201);
        let client = serde_json::from_str::<serde_json::Value>(&reg).unwrap()["client_id"].as_str().unwrap().to_string();

        let (status, headers, page) = call(o, "GET", &format!("/authorize?{}", ask(&client, CLAUDE)), "").await;
        assert_eq!(status, 200);
        assert!(page.contains("&lt;b&gt;Claude&lt;/b&gt;") && !page.contains("<b>Claude"), "{page}");
        assert!(page.contains("claude.ai") && !page.contains("<script") && !page.contains("src="));
        assert!(page.contains("Anyone can send you a link") && page.contains("The app calls itself: <strong>&lt;b&gt;"), "{page}");
        assert!(page.contains(&format!("name=\"code_challenge\" value=\"{}\"", challenge(VERIFIER))));
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(headers["x-frame-options"], "DENY");
        assert_eq!(headers["referrer-policy"], "no-referrer");
        let csp = headers["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'") && !csp.contains("form-action"));

        let (status, _, page) = call(o, "POST", "/authorize", &format!("{}&passphrase=wrong", ask(&client, CLAUDE))).await;
        assert_eq!(status, 403);
        assert!(page.contains("not right"));
        // Capitals and extra spaces, as a phone types them.
        let typed = "Amber  bison Cobalt dune ember fjord ";
        let (status, headers, _) = call(o, "POST", "/authorize", &format!("{}&passphrase={}", ask(&client, CLAUDE), pct(typed))).await;
        assert_eq!(status, 302);
        let code = query_of(headers["location"].to_str().unwrap()).get("code").unwrap().to_string();

        let (access, rt) = tokens(o, &client, &code).await;
        let g = o.check(&bearer(&access)).unwrap();
        assert_eq!(g.client, "<b>Claude</b>");
        let (status, v) = refresh(o, &rt).await;
        assert_eq!(status, 200, "{v}");
        let access2 = v["access_token"].as_str().unwrap();
        assert_eq!(o.check(&bearer(access2)).unwrap().id, g.id);
        o.check(&bearer(&access)).expect("the earlier access token lives to its own expiry");

        let list = grants(t.dir.path()).unwrap();
        assert_eq!((list.len(), list[0].calls, list[0].id.as_str()), (1, 3, g.id.as_str()));
        let events = t.events.lock().unwrap().join("\n");
        for kind in ["register", "consent_wrong", "consent_ok", "\"token\"", "refresh"] {
            assert!(events.contains(kind), "{kind} missing from {events}");
        }
        for secret in [access.as_str(), rt.as_str(), access2, code.as_str(), "amber", VERIFIER] {
            assert!(!events.contains(secret), "a secret is in the audit events");
        }
    }

    #[tokio::test]
    async fn discovery() {
        let t = setup();
        let o = &t.o;
        for path in ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"] {
            let (status, _, body) = call(o, "GET", path, "").await;
            assert_eq!(status, 200);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["resource"], URL);
            assert_eq!(v["authorization_servers"], json!(["https://mesh.example.com"]));
        }
        let (_, _, body) = call(o, "GET", "/.well-known/oauth-authorization-server", "").await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["issuer"], "https://mesh.example.com");
        assert_eq!(v["registration_endpoint"], "https://mesh.example.com/register");
        assert_eq!(v["code_challenge_methods_supported"], json!(["S256"]));
        assert!(v.get("client_id_metadata_document_supported").is_none());
        for path in ["/mcp", "/health", "/.well-known/openid-configuration", "/registerx"] {
            assert!(o.route(request("GET", path, "")).await.is_err(), "{path} was answered");
        }
        assert_eq!(call(o, "GET", "/token", "").await.0, 405);
        let r = o.check(&HeaderMap::new()).unwrap_err();
        assert_eq!(r.status(), 401);
        assert_eq!(r.headers()["www-authenticate"], "Bearer resource_metadata=\"https://mesh.example.com/.well-known/oauth-protected-resource/mcp\"");
    }

    #[tokio::test]
    async fn pkce_is_required_and_checked() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let base = format!("response_type=code&client_id={}&redirect_uri={}&state=s", pct(&client), pct(CLAUDE));
        for extra in ["", "&code_challenge=abc&code_challenge_method=plain", &format!("&code_challenge={}", challenge(VERIFIER))] {
            let (status, headers, _) = call(o, "GET", &format!("/authorize?{base}{extra}"), "").await;
            assert_eq!(status, 302, "{extra}");
            let q = query_of(headers["location"].to_str().unwrap());
            assert_eq!((q.get("error"), q.get("state")), (Some("invalid_request"), Some("s")));
        }
        let code = sign_in(o, &client, CLAUDE).await;
        let (status, v) = exchange(o, &client, &code, "another-verifier-of-fifty-characters-0123456789abc").await;
        assert_eq!((status, v["error"].as_str()), (400, Some("invalid_grant")));
        // The failed try used the code up.
        assert_eq!(exchange(o, &client, &code, VERIFIER).await.0, 400);
    }

    #[tokio::test]
    async fn codes_work_once_and_briefly() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let code = sign_in(o, &client, CLAUDE).await;
        let (access, _) = tokens(o, &client, &code).await;
        let (status, v) = exchange(o, &client, &code, VERIFIER).await;
        assert_eq!((status, v["error"].as_str()), (400, Some("invalid_grant")));
        assert!(o.check(&bearer(&access)).is_err(), "a code used twice must end its sign-in");
        assert!(t.events.lock().unwrap().iter().any(|e| e.contains("revoked_used")));

        let t = setup_with(|c| c.code_ttl = Duration::from_millis(1));
        let client = register(&t.o, CLAUDE).await;
        let code = sign_in(&t.o, &client, CLAUDE).await;
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(exchange(&t.o, &client, &code, VERIFIER).await.1["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn redirect_uris() {
        let t = setup();
        let o = &t.o;
        for bad in [
            "https://evil.example/cb",
            "https://claude.ai/api/mcp/auth_callback/x",
            "http://claude.ai/api/mcp/auth_callback",
            "http://localhost.evil.example/cb",
            "http://localhost@evil.example/cb",
            "http://127.0.0.1:80@evil.example/",
            "http://localhost:99999/cb",
            "https://localhost/cb",
            "http://localhost/cb#frag",
        ] {
            let (status, _, body) = call(o, "POST", "/register", &json!({"redirect_uris": [bad]}).to_string()).await;
            assert_eq!(status, 400, "{bad} was accepted");
            assert!(body.contains("invalid_redirect_uri"));
        }
        assert_eq!(call(o, "POST", "/register", "not json").await.0, 400);
        // Unknown grant types, auth methods and extra fields are ignored.
        let liberal = json!({"redirect_uris": ["https://claude.com/api/mcp/auth_callback"], "client_name": "Claude",
            "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "token_endpoint_auth_method": "client_secret_post", "logo_uri": "https://x/y.png"});
        assert_eq!(call(o, "POST", "/register", &liberal.to_string()).await.0, 201);

        // Loopback: any port, same path.
        let client = register(o, "http://127.0.0.1:3333/callback").await;
        let (_, _, page) = call(o, "GET", &format!("/authorize?{}", ask(&client, "http://127.0.0.1:4444/callback")), "").await;
        assert!(page.contains("<strong>127.0.0.1, an app on your own computer</strong>") && !page.contains("claude.ai"), "{page}");
        sign_in(o, &client, "http://127.0.0.1:4444/callback").await;
        let (status, headers, page) = call(o, "GET", &format!("/authorize?{}", ask(&client, "http://127.0.0.1:4444/other")), "").await;
        assert_eq!(status, 400);
        assert!(headers.get("location").is_none() && page.contains("not one this app registered"));
        let (status, headers, _) = call(o, "GET", &format!("/authorize?{}", ask(&client, "https://evil.example/cb")), "").await;
        assert_eq!(status, 400);
        assert!(headers.get("location").is_none());
        let (status, _, page) = call(o, "GET", &format!("/authorize?{}", ask("nobody", CLAUDE)), "").await;
        assert!(status == 400 && page.contains("not registered"));
    }

    #[tokio::test]
    async fn resource_must_be_the_url() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let base = ask(&client, CLAUDE).replace(&format!("&resource={}", pct(URL)), "");
        let (status, headers, _) = call(o, "GET", &format!("/authorize?{base}&resource={}", pct("https://mesh.example.com/other")), "").await;
        assert_eq!(status, 302);
        assert_eq!(query_of(headers["location"].to_str().unwrap()).get("error"), Some("invalid_target"));
        // Claude's canonical form, and no resource at all, are both fine.
        for extra in [format!("&resource={}", pct("https://MESH.example.com:443/mcp/")), String::new()] {
            assert_eq!(call(o, "GET", &format!("/authorize?{base}{extra}"), "").await.0, 200);
        }
        let code = sign_in(o, &client, CLAUDE).await;
        let body = format!("grant_type=authorization_code&code={}&code_verifier={VERIFIER}&client_id={}&resource={}", pct(&code), pct(&client), pct("https://evil.example/mcp"));
        let (_, _, body) = call(o, "POST", "/token", &body).await;
        assert!(body.contains("invalid_target"));
    }

    #[tokio::test]
    async fn access_tokens_expire() {
        let t = setup_with(|c| c.access_ttl = Duration::from_millis(1));
        let (_, access, _) = signed_in(&t.o).await;
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(t.o.check(&bearer(&access)).unwrap_err().status(), 401);
    }

    #[tokio::test]
    async fn old_access_token_lives_to_its_expiry() {
        // Seconds, not milliseconds: the sign-in and the refresh must fit inside the lifetime on a busy machine.
        let t = setup_with(|c| c.access_ttl = Duration::from_secs(3));
        let (_, a1, r1) = signed_in(&t.o).await;
        assert_eq!(refresh(&t.o, &r1).await.0, 200);
        t.o.check(&bearer(&a1)).unwrap();
        std::thread::sleep(Duration::from_millis(3100));
        assert!(t.o.check(&bearer(&a1)).is_err());
    }

    #[tokio::test]
    async fn reuse_inside_the_grace_is_only_refused() {
        let t = setup();
        let o = &t.o;
        let (_, _, r1) = signed_in(o).await;
        let (_, v) = refresh(o, &r1).await;
        let (a2, r2) = (v["access_token"].as_str().unwrap(), v["refresh_token"].as_str().unwrap());
        assert_eq!(refresh(o, &r1).await.1["error"], "invalid_grant");
        o.check(&bearer(a2)).unwrap();
        assert_eq!(refresh(o, r2).await.0, 200);
        assert_eq!(grants(t.dir.path()).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refresh_token_reuse_ends_the_sign_in() {
        let t = setup_with(|c| c.reuse_grace = Duration::from_millis(1));
        let o = &t.o;
        let (_, _, r1) = signed_in(o).await;
        let (_, v) = refresh(o, &r1).await;
        let (a2, r2) = (v["access_token"].as_str().unwrap(), v["refresh_token"].as_str().unwrap());
        std::thread::sleep(Duration::from_millis(10));
        let (status, v) = refresh(o, &r1).await;
        assert_eq!((status, v["error"].as_str()), (400, Some("invalid_grant")));
        assert!(t.events.lock().unwrap().iter().any(|e| e.contains("replaced_used")), "its own event, for the audit log's security group");
        assert!(o.check(&bearer(a2)).is_err());
        assert_eq!(refresh(o, r2).await.1["error"], "invalid_grant");
        assert!(grants(t.dir.path()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn nothing_without_a_sign_in() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        assert_eq!(exchange(o, &client, "made-up-code", VERIFIER).await.1["error"], "invalid_grant");
        assert_eq!(refresh(o, "made-up-refresh-token").await.1["error"], "invalid_grant");
        assert_eq!(o.check(&HeaderMap::new()).unwrap_err().status(), 401);
        assert_eq!(call(o, "POST", "/token", "grant_type=client_credentials").await.0, 400);
    }

    #[tokio::test]
    async fn forged_and_misplaced_tokens() {
        let t = setup();
        let o = &t.o;
        let (_, access, rt) = signed_in(o).await;
        let forged = B64.encode([7u8; 32]);
        let r = o.check(&bearer(&forged)).unwrap_err();
        assert_eq!(r.status(), 401);
        assert!(r.headers()["www-authenticate"].to_str().unwrap().contains("error=\"invalid_token\""));
        let mut basic = HeaderMap::new();
        basic.insert(header::AUTHORIZATION, format!("Basic {access}").parse().unwrap());
        assert!(o.check(&basic).is_err());
        let mut twice = bearer(&access);
        twice.append(header::AUTHORIZATION, format!("Bearer {access}").parse().unwrap());
        assert!(o.check(&twice).is_err());
        // Credentials in a query string are never read.
        let (status, _, _) = call(o, "POST", &format!("/token?grant_type=refresh_token&refresh_token={}", pct(&rt)), "").await;
        assert_eq!(status, 400);
        let client = register(o, CLAUDE).await;
        let (status, _, _) = call(o, "POST", &format!("/authorize?passphrase={}", pct(PHRASE)), &ask(&client, CLAUDE)).await;
        assert_eq!(status, 403);
        assert_eq!(refresh(o, &rt).await.0, 200, "the refresh token was used up by the query");
    }

    #[tokio::test]
    async fn no_lockout() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let wrong = format!("{}&passphrase=nope", ask(&client, CLAUDE));
        for _ in 0..10 {
            assert_eq!(call(o, "POST", "/authorize", &wrong).await.0, 403);
        }
        assert_eq!(t.events.lock().unwrap().iter().filter(|e| e.contains("consent_wrong")).count(), 10);
        sign_in(o, &client, CLAUDE).await;
    }

    #[tokio::test]
    async fn bodies_are_capped() {
        let t = setup();
        let big = "x".repeat(BODY_CAP + 1);
        for path in ["/register", "/token", "/authorize"] {
            assert_eq!(call(&t.o, "POST", path, &big).await.0, 413, "{path}");
        }
    }

    #[tokio::test]
    async fn registration_stores_nothing() {
        let t = setup();
        let o = &t.o;
        let size = || ["gateway.db", "gateway.db-wal"].iter().map(|f| std::fs::metadata(t.dir.path().join(f)).map_or(0, |m| m.len())).sum::<u64>();
        let before = size();
        let mut ids = Vec::new();
        for _ in 0..100 {
            ids.push(register(o, CLAUDE).await);
        }
        assert_eq!(size(), before);
        let rows: i64 = side_db(&t).query_row("SELECT (SELECT COUNT(*) FROM grants) + (SELECT COUNT(*) FROM codes) + (SELECT COUNT(*) FROM tokens)", [], |r| r.get(0)).unwrap();
        assert_eq!(rows, 0);
        // Any of them still signs in.
        sign_in(o, &ids[0], CLAUDE).await;
    }

    #[tokio::test]
    async fn client_ids_are_sealed() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let mut b = client.clone().into_bytes();
        b[5] = if b[5] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(b).unwrap();
        let other = setup();
        let foreign = register(&other.o, CLAUDE).await;
        for bad in [&tampered, &foreign] {
            let (status, _, page) = call(o, "GET", &format!("/authorize?{}", ask(bad, CLAUDE)), "").await;
            assert!(status == 400 && page.contains("not registered"), "{page}");
            assert_eq!(call(o, "POST", "/authorize", &format!("{}&passphrase={}", ask(bad, CLAUDE), pct(PHRASE))).await.0, 400);
            let (status, v) = exchange(o, bad, "made-up-code", VERIFIER).await;
            assert_eq!((status, v["error"].as_str()), (401, Some("invalid_client")));
        }
        // A real code with a tampered id is refused too.
        let code = sign_in(o, &client, CLAUDE).await;
        assert_eq!(exchange(o, &tampered, &code, VERIFIER).await.0, 401);
    }

    #[tokio::test]
    async fn registration_limits() {
        let t = setup();
        let o = &t.o;
        let six: Vec<String> = (0..6).map(|i| format!("http://localhost:{}/cb", 3000 + i)).collect();
        let long = format!("http://localhost/{}", "x".repeat(MAX_REDIRECT_LEN - 17));
        let five: Vec<String> = (0..5).map(|_| long.clone()).collect();
        for uris in [json!(six), json!([format!("{long}y")]), json!(five)] {
            let (status, _, body) = call(o, "POST", "/register", &json!({"redirect_uris": uris}).to_string()).await;
            assert_eq!(status, 400, "{body}");
        }
        let id = register(o, &long).await;
        assert!(id.len() < 2000);
        // Escape sequences a terminal would act on come back clean, and the name is cut to 64 characters.
        let name = format!("\u{1b}[2J\u{1b}]0;pwned\u{7}Cl\u{9b}31maude\u{202e}{}", "x".repeat(100));
        let (_, _, body) = call(o, "POST", "/register", &json!({"client_name": name, "redirect_uris": [CLAUDE]}).to_string()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let clean = v["client_name"].as_str().unwrap();
        assert!(clean.starts_with("[2J]0;pwnedCl31maude") && clean.chars().count() == 64, "{clean}");
        assert!(!clean.chars().any(|c| c.is_control() || c == '\u{202e}'));
        let client = v["client_id"].as_str().unwrap();
        let code = sign_in(o, client, CLAUDE).await;
        tokens(o, client, &code).await;
        assert_eq!(grants(t.dir.path()).unwrap()[0].client, clean);
    }

    #[tokio::test]
    async fn slow_bodies_time_out() {
        // Sign-in bodies are tiny: 5 s is plenty, and a trickling one frees its connection soon.
        assert_eq!(Config::new(URL, Path::new(".")).unwrap().body_timeout, Duration::from_secs(5));
        let t = setup_with(|c| c.body_timeout = Duration::from_millis(100));
        // One byte, then nothing more.
        struct Stall(bool);
        impl Body for Stall {
            type Data = Bytes;
            type Error = std::convert::Infallible;
            fn poll_frame(
                mut self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
                if std::mem::replace(&mut self.0, true) {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(b"g")))))
            }
        }
        let req = http::Request::builder().method("POST").uri("/token").body(Stall(false)).unwrap();
        let r = t.o.route(req).await.unwrap_or_else(|_| panic!("not answered"));
        assert_eq!(r.status(), 408);
    }

    #[tokio::test]
    async fn ending_all_sign_ins_ends_codes_under_way() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let code = sign_in(o, &client, CLAUDE).await;
        revoke(t.dir.path(), None).unwrap();
        assert_eq!(exchange(o, &client, &code, VERIFIER).await.1["error"], "invalid_grant");
        assert!(grants(t.dir.path()).unwrap().is_empty());
    }

    #[tokio::test]
    async fn sign_ins_are_capped() {
        let t = setup();
        let o = &t.o;
        let client = register(o, CLAUDE).await;
        let mut access = Vec::new();
        for _ in 0..MAX_GRANTS {
            let code = sign_in(o, &client, CLAUDE).await;
            access.push(tokens(o, &client, &code).await.0);
            std::thread::sleep(Duration::from_millis(2));
        }
        // The first is used now, so the second is the one unused for longest.
        o.check(&bearer(&access[0])).unwrap();
        let code = sign_in(o, &client, CLAUDE).await;
        let newest = tokens(o, &client, &code).await.0;
        assert_eq!(grants(t.dir.path()).unwrap().len(), MAX_GRANTS as usize);
        assert!(o.check(&bearer(&access[1])).is_err());
        o.check(&bearer(&access[0])).unwrap();
        o.check(&bearer(&newest)).unwrap();
    }

    #[tokio::test]
    async fn commands_work_while_the_gateway_runs() {
        let t = setup();
        let o = &t.o;
        let dir = t.dir.path();
        let (_, a1, r1) = signed_in(o).await;
        let (_, a2, _) = signed_in(o).await;
        let (_, a3, _) = signed_in(o).await;
        let g1 = o.check(&bearer(&a1)).unwrap();
        let list = grants(dir).unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!((list[0].id.as_str(), list[0].calls), (g1.id.as_str(), 1));
        assert_eq!(revoke(dir, Some(&g1.id)).unwrap(), 1);
        assert_eq!(revoke(dir, Some("no-such-id")).unwrap(), 0);
        assert!(o.check(&bearer(&a1)).is_err());
        assert!(t.events.lock().unwrap().iter().any(|e| e.contains("revoked_used")));
        assert_eq!(refresh(o, &r1).await.1["error"], "invalid_grant");
        o.check(&bearer(&a2)).unwrap();
        assert_eq!(revoke(dir, None).unwrap(), 2);
        assert!(o.check(&bearer(&a2)).is_err() && o.check(&bearer(&a3)).is_err());

        assert!(has_passphrase(dir).unwrap());
        set_passphrase(dir, "new words here for this test").unwrap();
        let client = register(o, CLAUDE).await;
        let old = format!("{}&passphrase={}", ask(&client, CLAUDE), pct(PHRASE));
        assert_eq!(call(o, "POST", "/authorize", &old).await.0, 403);
        let empty = tempfile::tempdir().unwrap();
        assert!(!has_passphrase(empty.path()).unwrap());
    }

    #[tokio::test]
    async fn no_passphrase_no_sign_in() {
        let dir = tempfile::tempdir().unwrap();
        let o = OAuth::open(Config::new(URL, dir.path()).unwrap(), Arc::new(|_: &Event| {})).unwrap();
        let client = register(&o, CLAUDE).await;
        assert_eq!(call(&o, "GET", &format!("/authorize?{}", ask(&client, CLAUDE)), "").await.0, 503);
        assert_eq!(call(&o, "POST", "/authorize", &format!("{}&passphrase=", ask(&client, CLAUDE))).await.0, 503);
    }

    #[test]
    fn config_urls() {
        let dir = Path::new("/nonexistent");
        for good in ["https://mesh.example.com/mcp", "https://mesh.example.com", "http://127.0.0.1:8787/mcp", "http://localhost/mcp"] {
            Config::new(good, dir).unwrap();
        }
        for bad in ["http://mesh.example.com/mcp", "https://h/mcp?x=1", "https://h/mcp#f", "ftp://h/mcp", "https://u@h/mcp", "https://h:x/mcp", "https:///mcp", "https://h/m cp"] {
            assert!(Config::new(bad, dir).is_err(), "{bad} was accepted");
        }
        assert_eq!(canonical("HTTPS://Mesh.Example.com:443/mcp/").as_deref(), Some("https://mesh.example.com/mcp"));
    }

    #[cfg(unix)]
    #[test]
    fn database_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        set_passphrase(dir.path(), PHRASE).unwrap();
        let mode = std::fs::metadata(dir.path().join("gateway.db")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let stored: Vec<u8> = open_db(dir.path()).unwrap().query_row("SELECT hash FROM secret", [], |r| r.get(0)).unwrap();
        assert_ne!(stored, PHRASE.as_bytes());
    }
}
