//! `tearmesh update`: installs a newer published release in place, by hand or because the
//! membership file names it (spec 22.3). It runs as root and installs a program, so it installs
//! only a download whose SHA-256 is the one SHA256SUMS lists and that reports the version expected,
//! never an older one, and takes nothing from the membership file or the daemon but a version.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use sha2::Digest;

use crate::install::{RELEASES, release_url};
use crate::mesh::{Mesh, release_version};

pub type Version = (u64, u64, u64);

const LATEST: &str = "https://github.com/maxwell-tablinum/tear-mesh/releases/latest";
const TAG: &str = "https://github.com/maxwell-tablinum/tear-mesh/releases/tag/v";

pub fn show(v: Version) -> String {
    format!("{}.{}.{}", v.0, v.1, v.2)
}

fn this_version() -> Version {
    release_version(env!("CARGO_PKG_VERSION")).expect("the crate version is three numbers")
}

/// The release binary for this system.
fn asset() -> Result<&'static str> {
    Ok(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "tearmesh-x86_64-linux",
        ("linux", "aarch64") => "tearmesh-aarch64-linux",
        ("windows", "x86_64") => "tearmesh-x86_64-windows.exe",
        (os, arch) => bail!("there is no release binary for {arch} {os}"),
    })
}

/// The version at the end of the URL `releases/latest` leads to, `…/releases/tag/vX.Y.Z`.
fn tag_version(url: &str) -> Option<Version> {
    release_version(url.strip_prefix(TAG)?)
}

fn client() -> Result<reqwest::Client> {
    // reqwest is built without a crypto provider; use ring, as iroh does.
    let _ = rustls::crypto::ring::default_provider().install_default();
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::custom(|a| {
            if a.previous().len() >= 10 {
                a.error("too many redirects")
            } else if a.previous()[0].scheme() == "https" && a.url().scheme() != "https" {
                a.error("a download over https was redirected to plain http")
            } else {
                a.follow()
            }
        }))
        .build()?)
}

async fn latest(http: &reqwest::Client) -> Result<Version> {
    let r = http.get(LATEST).send().await.and_then(|r| r.error_for_status()).context("looking up the newest release")?;
    tag_version(r.url().as_str()).with_context(|| format!("{LATEST} led to {}, which names no release", r.url()))
}

async fn get(http: &reqwest::Client, url: &str) -> Result<bytes::Bytes> {
    let r = http.get(url).send().await.and_then(|r| r.error_for_status()).with_context(|| format!("downloading {url}"))?;
    r.bytes().await.with_context(|| format!("downloading {url}"))
}

/// Downloads `asset` and SHA256SUMS from the folder `base` into `dir`, checks the hash and that
/// the binary reports `want` (any version when None). Returns the binary and its version, or None
/// when that version is not newer than `installed`. Nothing that failed a check is ever run but
/// for `--version` after the hash matched.
pub async fn fetch(http: &reqwest::Client, base: &str, asset: &str, dir: &Path, want: Option<Version>, installed: Version) -> Result<Option<(PathBuf, Version)>> {
    let sums = get(http, &format!("{base}/SHA256SUMS")).await?;
    let sums = String::from_utf8_lossy(&sums);
    let sum = sums
        .lines()
        .find_map(|l| {
            let (h, name) = l.split_once(' ')?;
            (name.trim_start_matches([' ', '*']) == asset).then_some(h)
        })
        .with_context(|| format!("SHA256SUMS lists no {asset}: not installing"))?;
    let bin = get(http, &format!("{base}/{asset}")).await?;
    ensure!(
        crate::envelope::hex(&sha2::Sha256::digest(&bin)).eq_ignore_ascii_case(sum),
        "checksum mismatch: not installing"
    );
    let path = dir.join(asset);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o700);
    std::io::Write::write_all(&mut o.open(&path)?, &bin).with_context(|| format!("writing {}", path.display()))?;
    let out = Command::new(&path).arg("--version").stdin(Stdio::null()).output().context("running the downloaded binary")?;
    let said = String::from_utf8_lossy(&out.stdout);
    let v = said
        .trim()
        .strip_prefix("tearmesh ")
        .and_then(release_version)
        .filter(|_| out.status.success())
        .context("the downloaded binary doesn't report a version: not installing")?;
    if let Some(w) = want {
        ensure!(v == w, "the downloaded binary is {}, not {}: not installing", show(v), show(w));
    }
    Ok((v > installed).then_some((path, v)))
}

/// The folder the download is put in and run from, and the file that keeps two updates from
/// running at once. The folder is beside the installed binary: only root (an Administrator)
/// writes there, and unlike the temp directory it is never mounted noexec.
fn work_paths() -> (PathBuf, PathBuf) {
    // On Windows the lock is in the data folder, which ordinary users can't read.
    #[cfg(windows)]
    {
        (crate::install::plugin_dir().join(".update"), Path::new(crate::install::CONFIG).with_file_name("update.lock"))
    }
    #[cfg(not(windows))]
    ("/usr/local/bin/.tearmesh-update".into(), "/run/tearmesh-update.lock".into())
}

/// The release the newest membership file in `state` names. The daemon, not root, writes these
/// files, so only a version is taken from them, read with a size limit and never through a link.
fn stored_release(state: &Path) -> Result<Option<Version>> {
    use std::io::Read;
    let rd = match std::fs::read_dir(state.join("mesh")) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("reading the membership files"),
    };
    let newest = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .filter_map(|p| Some((p.file_stem()?.to_str()?.parse::<u64>().ok()?, p)))
        .max_by_key(|(v, _)| *v);
    let Some((_, p)) = newest else { return Ok(None) };
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, (nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_NONBLOCK).bits());
    let f = o.open(&p).with_context(|| format!("reading {}", p.display()))?;
    ensure!(f.metadata()?.is_file(), "{} isn't a file", p.display());
    let mut b = vec![];
    f.take(4 * crate::mesh::MAX_FILE as u64).read_to_end(&mut b)?;
    #[derive(serde::Deserialize)]
    struct Stored {
        toml: String,
    }
    let s: Stored = serde_json::from_slice(&b).with_context(|| format!("reading {}", p.display()))?;
    let m = Mesh::parse(&s.toml).with_context(|| format!("reading {}", p.display()))?;
    Ok(m.settings.release.as_deref().and_then(release_version))
}

/// `tearmesh update [--to VERSION] [--mesh]`.
pub async fn run(to: Option<&str>, mesh: bool) -> Result<()> {
    crate::install::require_admin("update")?;
    let installed = this_version();
    let Some(cfg) = crate::install::installed() else {
        // The updater's timer outlives nothing; quiet when there is nothing to update.
        if mesh {
            return Ok(());
        }
        bail!("tear-mesh isn't installed on this machine: sudo tearmesh install");
    };
    let want = match to {
        Some(t) => Some(release_version(t).with_context(|| format!("--to takes a version like 0.5.1, not {t:?}"))?),
        None if mesh => match stored_release(&cfg.state_dir)? {
            Some(v) if v > installed => Some(v),
            // Nothing to do, and no connection made.
            _ => return Ok(()),
        },
        None => None,
    };
    println!("installed: tearmesh {}", show(installed));
    if let Some(w) = want {
        if w <= installed {
            println!("already at {}", show(installed));
            return Ok(());
        }
        println!("{}: {}", if mesh { "the mesh names" } else { "asked for" }, show(w));
    }
    let http = client()?;
    let over = std::env::var("TEARMESH_RELEASE_URL").ok();
    let (base, want) = match (over.as_deref().and_then(release_url), want) {
        (Some(u), w) => {
            println!("downloading from {u} (TEARMESH_RELEASE_URL)");
            (u.to_string(), w)
        }
        (None, Some(w)) => (format!("{RELEASES}/v{}", show(w)), Some(w)),
        (None, None) => {
            let v = latest(&http).await?;
            println!("newest release: {}", show(v));
            if v <= installed {
                println!("already at {}", show(installed));
                return Ok(());
            }
            (format!("{RELEASES}/v{}", show(v)), Some(v))
        }
    };
    let (dir, lock) = work_paths();
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(false);
    // Whoever can open a lock file can hold the lock, and so keep updates away: root only.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let held = o.open(&lock).with_context(|| format!("opening {}", lock.display()))?;
    match held.try_lock() {
        Ok(()) => {}
        // The timer and a person at once: the first one does the work.
        Err(std::fs::TryLockError::WouldBlock) if mesh => return Ok(()),
        Err(std::fs::TryLockError::WouldBlock) => bail!("another update is running on this machine"),
        Err(std::fs::TryLockError::Error(e)) => return Err(e).with_context(|| format!("locking {}", lock.display())),
    }
    // Under the lock, whatever is there was left by a run that was cut short.
    let _ = std::fs::remove_dir_all(&dir);
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let r = async {
        let Some((exe, v)) = fetch(&http, &base, asset()?, &dir, want, installed).await? else {
            println!("already at {}", show(installed));
            return Ok(());
        };
        println!("downloaded tearmesh {}: its SHA-256 matches SHA256SUMS; installing it as machine {}", show(v), cfg.machine);
        let st = Command::new(&exe).arg("install").arg(&cfg.machine).stdin(Stdio::null()).status().context("running the new binary's install")?;
        ensure!(st.success(), "the install of {} stopped ({st}); this machine still runs {}", show(v), show(installed));
        println!("updated from {} to {}", show(installed), show(v));
        Ok(())
    }
    .await;
    let _ = std::fs::remove_dir_all(&dir);
    r
}

/// `tearmesh update --check`: looks, changes nothing, needs no rights.
pub async fn check() -> Result<()> {
    let installed = this_version();
    println!("installed: tearmesh {}", show(installed));
    let over = std::env::var("TEARMESH_RELEASE_URL").ok();
    let over = over.as_deref().and_then(release_url);
    let newest = match over {
        Some(u) => {
            println!("newest release: whichever {u} holds (TEARMESH_RELEASE_URL); update checks its version");
            None
        }
        None => match latest(&client()?).await {
            Ok(v) => {
                println!("newest release: {}", show(v));
                Some(v)
            }
            Err(e) => {
                println!("newest release: couldn't look it up ({e:#})");
                None
            }
        },
    };
    // The daemon's status first (admins), else the state directory (root), else nothing.
    let status = async { crate::ipc::Client::connect(&crate::ipc::socket_path()).await?.call(&crate::ipc::Request::Status).await }.await.ok();
    let named = match &status {
        Some(s) => Some(s["mesh"]["release"].as_str().and_then(release_version)),
        None => crate::install::installed().and_then(|c| stored_release(&c.state_dir).ok()),
    };
    match named {
        Some(Some(v)) => println!("the mesh names: {}", show(v)),
        Some(None) => println!("the mesh names no release"),
        None => {}
    }
    let cmd = if cfg!(windows) { "tearmesh update (in an elevated prompt)" } else { "sudo tearmesh update" };
    if newest.is_some_and(|v| v > installed) || named.flatten().is_some_and(|v| v > installed) || over.is_some() {
        println!("To update this machine: {cmd}");
    } else if newest.is_some() {
        println!("This machine is up to date.");
    }
    let owners: Vec<String> = status
        .as_ref()
        .and_then(|s| serde_json::from_value(s["mesh"]["owners"].clone()).ok())
        .unwrap_or_default();
    if let Some(v) = newest
        && v >= installed
        && named.flatten() < Some(v)
        && !owners.is_empty()
        && !crate::setup::find_owner_keys(&owners).is_empty()
    {
        println!("To update every machine of the mesh: tearmesh mesh set release {}", show(v));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_as_numbers_and_the_tag_is_read() {
        assert!(release_version("0.10.0") > release_version("0.9.9"));
        assert!(release_version("1.0.0") > release_version("0.99.99"));
        assert_eq!(tag_version("https://github.com/maxwell-tablinum/tear-mesh/releases/tag/v0.5.1"), Some((0, 5, 1)));
        for bad in [
            "https://github.com/maxwell-tablinum/tear-mesh/releases",
            "https://github.com/maxwell-tablinum/tear-mesh/releases/tag/0.5.1",
            "https://github.com/maxwell-tablinum/tear-mesh/releases/tag/v0.5.1-rc1",
            "https://github.com/other/tear-mesh/releases/tag/v0.5.1",
        ] {
            assert_eq!(tag_version(bad), None, "{bad}");
        }
        assert_eq!(show(this_version()), env!("CARGO_PKG_VERSION"));
    }

    /// Serves `dir` over 127.0.0.1, one request per connection; returns the folder's URL.
    fn serve(dir: PathBuf) -> String {
        use std::io::{BufRead, BufReader, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut line = String::new();
                let _ = BufReader::new(&s).read_line(&mut line);
                let name = line.split(' ').nth(1).unwrap_or("/").trim_start_matches('/').to_string();
                let r = match std::fs::read(dir.join(&name)) {
                    Ok(b) => [format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len()).into_bytes(), b].concat(),
                    Err(_) => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
                };
                let _ = s.write_all(&r);
            }
        });
        url
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_download_is_installed_only_when_every_check_passes() {
        let srv = tempfile::tempdir().unwrap();
        let bin = b"#!/bin/sh\necho 'tearmesh 9.9.9'\n";
        std::fs::write(srv.path().join("tm"), bin).unwrap();
        let good = crate::envelope::hex(&sha2::Sha256::digest(bin));
        let base = serve(srv.path().to_path_buf());
        let http = client().unwrap();
        let sums = |s: &str| std::fs::write(srv.path().join("SHA256SUMS"), s).unwrap();
        let try_ = |want: Option<Version>, installed: Version| {
            let (http, base) = (http.clone(), base.clone());
            async move {
                let out = tempfile::tempdir().unwrap();
                let r = fetch(&http, &base, "tm", out.path(), want, installed).await;
                (r, std::fs::read_dir(out.path()).unwrap().count())
            }
        };

        sums(&format!("{}  tearmesh.mcpb\n{good}  tm\n", "0".repeat(64)));
        let (r, _) = try_(Some((9, 9, 9)), (0, 5, 0)).await;
        let (path, v) = r.unwrap().unwrap();
        assert_eq!(v, (9, 9, 9));
        assert!(path.ends_with("tm"));
        assert_eq!(try_(None, (0, 5, 0)).await.0.unwrap().unwrap().1, (9, 9, 9), "the version on offer is the binary's");
        assert!(try_(None, (9, 9, 9)).await.0.unwrap().is_none(), "not newer: not installed");
        assert!(try_(None, (10, 0, 0)).await.0.unwrap().is_none(), "never backwards");
        let e = try_(Some((9, 9, 8)), (0, 5, 0)).await.0.unwrap_err().to_string();
        assert!(e.contains("is 9.9.9, not 9.9.8: not installing"), "{e}");

        sums(&format!("{}  tm\n", "1".repeat(64)));
        let (r, left) = try_(None, (0, 5, 0)).await;
        assert_eq!(r.unwrap_err().to_string(), "checksum mismatch: not installing");
        assert_eq!(left, 0, "a download that failed its check is never written");

        sums(&format!("{good}  tm-other\n"));
        let e = try_(None, (0, 5, 0)).await.0.unwrap_err().to_string();
        assert!(e.contains("SHA256SUMS lists no tm"), "{e}");
    }

    #[test]
    fn the_release_comes_from_the_newest_stored_file() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(stored_release(d.path()).unwrap(), None, "no mesh yet");
        let (_, a) = crate::mesh::tests::keygen(d.path(), "a");
        let (_, b) = crate::mesh::tests::keygen(d.path(), "b");
        let mut m = Mesh::new("home", vec![a, b], vec!["work".into()], None).unwrap();
        std::fs::create_dir(d.path().join("mesh")).unwrap();
        let put = |v: u64, m: &Mesh| {
            let j = serde_json::json!({ "toml": m.to_toml().unwrap(), "sig": "" });
            std::fs::write(d.path().join(format!("mesh/{v}.json")), j.to_string()).unwrap();
        };
        put(1, &m);
        assert_eq!(stored_release(d.path()).unwrap(), None);
        m.settings.release = Some("0.12.3".into());
        put(10, &m);
        m.settings.release = Some("9.0.0".into());
        put(9, &m);
        assert_eq!(stored_release(d.path()).unwrap(), Some((0, 12, 3)), "10 is newer than 9");
        std::fs::write(d.path().join("mesh/11.json"), "{\"toml\": \"[settings]\\nrelease = \\\"1.0.0\\\"\\n\"}").unwrap();
        assert!(stored_release(d.path()).is_err(), "a file that isn't a valid membership file gives nothing");
        #[cfg(unix)]
        {
            std::fs::remove_file(d.path().join("mesh/11.json")).unwrap();
            std::os::unix::fs::symlink("/dev/zero", d.path().join("mesh/12.json")).unwrap();
            assert!(stored_release(d.path()).is_err(), "never through a link");
        }
    }
}
