#!/usr/bin/env python3
"""A stand-in for Claude's connector client, for testing a tear-mesh gateway without Claude.
It does what Claude does: finds the sign-in server from the 401, registers, signs in with PKCE,
keeps the tokens in a file, refreshes them, and calls tools. Standard library only.

  gateway-client.py URL signin PASSPHRASE      # URL is the connector URL, e.g. https://host/mcp
  gateway-client.py URL tools
  gateway-client.py URL call TOOL ['{"json": "arguments"}']
  gateway-client.py URL refresh

--via http://127.0.0.1:8787 connects there instead of to URL's host (a gateway with no tunnel yet).
--state FILE keeps the tokens somewhere else than ./gateway-client.json.
"""
import base64, hashlib, json, os, secrets, sys, urllib.error, urllib.parse, urllib.request

CALLBACK = "https://claude.ai/api/mcp/auth_callback"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    def __init__(self, url, via=None, state="gateway-client.json"):
        self.url, self.via, self.state_file = url, via, state
        self.opener = urllib.request.build_opener(NoRedirect)
        self.state = json.load(open(state)) if os.path.exists(state) else {}

    def save(self):
        with open(os.open(self.state_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(self.state, f)

    def http(self, method, url, body=None, headers=None):
        """Returns (status, headers, text). With --via, the same path is asked of that address."""
        if self.via:
            u = urllib.parse.urlsplit(url)
            url = self.via.rstrip("/") + u.path + ("?" + u.query if u.query else "")
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=60) as r:
                return r.status, r.headers, r.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read().decode()

    def form(self, url, fields):
        return self.http("POST", url, urllib.parse.urlencode(fields).encode(),
                         {"content-type": "application/x-www-form-urlencoded"})

    def discover(self):
        status, headers, _ = self.http("POST", self.url, b"{}", {"content-type": "application/json"})
        assert status == 401, f"expected 401 without a token, got {status}"
        www = headers.get("WWW-Authenticate", "")
        assert 'resource_metadata="' in www, f"no resource_metadata in WWW-Authenticate: {www!r}"
        prm_url = www.split('resource_metadata="')[1].split('"')[0]
        prm = json.loads(self.http("GET", prm_url)[2])
        assert prm["resource"] == self.url, f"resource is {prm['resource']!r}, not the connector URL"
        meta = json.loads(self.http("GET", prm["authorization_servers"][0].rstrip("/") + "/.well-known/oauth-authorization-server")[2])
        assert "S256" in meta["code_challenge_methods_supported"]
        return meta

    def signin(self, passphrase):
        meta = self.discover()
        status, _, text = self.http("POST", meta["registration_endpoint"],
                                    json.dumps({"client_name": "Claude (test client)", "redirect_uris": [CALLBACK]}).encode(),
                                    {"content-type": "application/json"})
        assert status in (200, 201), f"registration: {status} {text}"
        client_id = json.loads(text)["client_id"]
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"response_type": "code", "client_id": client_id, "redirect_uri": CALLBACK, "state": secrets.token_urlsafe(8),
             "code_challenge": challenge, "code_challenge_method": "S256", "resource": self.url, "scope": "offline_access"}
        status, _, page = self.http("GET", meta["authorization_endpoint"] + "?" + urllib.parse.urlencode(q))
        assert status == 200, f"sign-in page: {status} {page[:200]}"
        status, headers, text = self.form(meta["authorization_endpoint"], {**q, "passphrase": passphrase})
        assert status in (302, 303), f"sign-in refused: {status} {text[:300]}"
        back = urllib.parse.urlsplit(headers["Location"])
        got = urllib.parse.parse_qs(back.query)
        assert headers["Location"].startswith(CALLBACK) and got["state"][0] == q["state"], headers["Location"]
        status, _, text = self.form(meta["token_endpoint"], {"grant_type": "authorization_code", "code": got["code"][0], "client_id": client_id,
                                                             "redirect_uri": CALLBACK, "code_verifier": verifier, "resource": self.url})
        assert status == 200, f"token: {status} {text}"
        self.state = {"client_id": client_id, "token_endpoint": meta["token_endpoint"], **json.loads(text)}
        self.save()
        return sorted(self.state)

    def refresh(self):
        status, _, text = self.form(self.state["token_endpoint"], {"grant_type": "refresh_token", "refresh_token": self.state["refresh_token"],
                                                                   "client_id": self.state["client_id"], "resource": self.url})
        assert status == 200, f"refresh: {status} {text}"
        self.state.update(json.loads(text))
        self.save()

    def rpc(self, method, params=None, token=None):
        """One MCP request. Returns (status, parsed body or text)."""
        body = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            body["params"] = params
        status, headers, text = self.http("POST", self.url, json.dumps(body).encode(), {
            "content-type": "application/json", "accept": "application/json, text/event-stream",
            "mcp-protocol-version": "2025-11-25", "authorization": "Bearer " + (token or self.state.get("access_token", ""))})
        if status == 401 and token is None and self.state.get("refresh_token"):
            self.refresh()  # as Claude does on a 401
            return self.rpc(method, params, self.state["access_token"])
        if "text/event-stream" in (headers.get("content-type") or ""):
            text = [l[5:].strip() for l in text.splitlines() if l.startswith("data:")][-1]
        try:
            return status, json.loads(text)
        except ValueError:
            return status, text

    def call(self, tool, args=None):
        """A tool call. Returns (ok, value): the tool's JSON result, or its error text."""
        status, r = self.rpc("tools/call", {"name": tool, "arguments": args or {}})
        if status != 200 or "result" not in r:
            return False, f"{status} {r}"
        text = "".join(c.get("text", "") for c in r["result"].get("content", []))
        if r["result"].get("isError"):
            return False, text
        try:
            return True, json.loads(text)
        except ValueError:
            return True, text


def main(argv):
    opts = {}
    while len(argv) > 1 and argv[0] in ("--via", "--state"):
        opts[argv[0][2:]] = argv[1]
        argv = argv[2:]
    if len(argv) < 2:
        sys.exit(__doc__)
    c = Client(argv[0], **opts)
    cmd = argv[1]
    if cmd == "signin":
        print("signed in; got:", ", ".join(c.signin(argv[2])))
    elif cmd == "refresh":
        c.refresh()
        print("refreshed")
    elif cmd == "tools":
        c.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "gateway-client", "version": "0"}})
        for t in c.rpc("tools/list")[1]["result"]["tools"]:
            print(t["name"], t.get("annotations", {}))
    elif cmd == "call":
        ok, v = c.call(argv[2], json.loads(argv[3]) if len(argv) > 3 else {})
        print(json.dumps(v, indent=1, ensure_ascii=False) if ok else "ERROR: " + str(v))
        sys.exit(0 if ok else 1)
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
