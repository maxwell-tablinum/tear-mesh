//! Windows: a named pipe. The daemon identifies a caller by impersonating the client's token after
//! its first line; a client refuses a pipe that the daemon didn't create.

use std::ffi::{OsStr, OsString, c_void};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_sys::Win32::Foundation::{
    ERROR_PIPE_BUSY, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
    GetTokenInformation, LookupAccountNameW, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};
use windows_sys::core::BOOL;

use super::{BoxRead, BoxWrite, Caller, Incoming};
use crate::config::Config;

const SYSTEM: &str = "S-1-5-18";
#[cfg(test)]
const LOCAL_SERVICE: &str = "S-1-5-19";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const SERVICE_NAME: &str = "tearmesh";
/// The virtual account `deploy/setup-windows.ps1` runs the service as.
const SERVICE_ACCOUNT: &str = r"NT SERVICE\tearmesh";

pub struct Listener {
    name: OsString,
    sd: Local,
    me: String,
    next: tokio::sync::Mutex<NamedPipeServer>,
}

/// SYSTEM, Administrators and the daemon's user get full access. Authenticated Users get read and
/// write (0x12019b, which leaves out FILE_CREATE_PIPE_INSTANCE, so nobody else can add a server
/// end to this pipe). Other machines are refused by `reject_remote_clients`; local network logons
/// such as SSH sessions are let in, as the user they are.
fn pipe_sddl(owner: &str, me: &str) -> String {
    format!("O:{owner}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{me})(A;;0x12019b;;;AU)")
}

fn create(name: &OsStr, sd: &Local, first: bool) -> io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `sa` and the descriptor it points to outlive the call.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut sa).cast())
    }
}

pub async fn listen(path: &Path) -> Result<Listener> {
    let me = process_user()?;
    // A client trusts the pipe by its owner (see `verify_server`). An elevated admin's daemon
    // can name Administrators; any other daemon names its own user.
    let owner = if is_member(null_mut(), ADMINISTRATORS)? {
        "BA"
    } else {
        &me
    };
    let sd = security_descriptor(&pipe_sddl(owner, &me))?;
    let name = path.as_os_str().to_owned();
    // The first instance fails if the name exists, so a program that took it first can't pose
    // as the daemon: the daemon stops instead.
    let first = create(&name, &sd, true).with_context(|| {
        format!(
            "creating the pipe {} (does another program have it?)",
            path.display()
        )
    })?;
    Ok(Listener {
        name,
        sd,
        me,
        next: tokio::sync::Mutex::new(first),
    })
}

impl Listener {
    pub async fn accept(&self) -> Result<Incoming> {
        let mut next = self.next.lock().await;
        let connected = next.connect().await;
        // Make the next instance before handing this one off, so the name never lapses.
        let pipe = std::mem::replace(&mut *next, create(&self.name, &self.sd, false)?);
        connected?;
        // An owned duplicate: the closure can't outlive the pipe it identifies.
        let handle = pipe.as_handle().try_clone_to_owned()?;
        let me = self.me.clone();
        let (r, w) = tokio::io::split(pipe);
        Ok(Incoming {
            read: Box::new(r),
            write: Box::new(w),
            caller: Box::new(move || client(&handle, &me)),
        })
    }
}

/// The client's user, and whether it's an admin: an elevated Administrator (a UAC-filtered token
/// holds Administrators as deny-only, so CheckTokenMembership says no), SYSTEM, or the daemon's
/// own user.
fn client(pipe: &OwnedHandle, me: &str) -> Result<Caller> {
    let token = client_token(pipe)?;
    let id = token_user(token.as_raw_handle())?;
    let admin = id == SYSTEM || id == me || is_member(token.as_raw_handle(), ADMINISTRATORS)?;
    Ok(Caller { id, admin })
}

/// The client's token, impersonating the client only while it's opened.
fn client_token(pipe: &OwnedHandle) -> Result<OwnedHandle> {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            // A thread left impersonating would go on acting as the client.
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    let _revert = Revert;
    if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
        bail!(
            "identifying the pipe client: {}",
            io::Error::last_os_error()
        );
    }
    let mut t = null_mut();
    // OpenAsSelf: an identification-level token can't open objects, its own token included.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut t) } == 0 {
        bail!(
            "opening the pipe client's token: {}",
            io::Error::last_os_error()
        );
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(t) })
}

pub async fn connect(path: &Path) -> Result<(BoxRead, BoxWrite)> {
    let ctx = || format!("connecting to the tear-mesh daemon at {}", path.display());
    let mut tries = 0;
    let pipe = loop {
        match open(path) {
            Ok(p) => break p,
            // Every instance is taken; the daemon makes the next one at once.
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e).with_context(ctx),
        }
    };
    verify_server(&pipe).with_context(ctx)?;
    let (r, w) = tokio::io::split(pipe);
    Ok((Box::new(r), Box::new(w)))
}

/// Opens the pipe for read and write-data only: tokio's `ClientOptions` asks for GENERIC_WRITE,
/// which includes FILE_CREATE_PIPE_INSTANCE, which the pipe grants no client. Identification
/// level: the daemon can tell who this is but can't act as it.
fn open(path: &Path) -> io::Result<NamedPipeClient> {
    let h = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an overlapped pipe handle this function owns.
    unsafe { NamedPipeClient::from_raw_handle(h) }
}

/// Refuses a pipe the daemon didn't create; another program may have claimed the name. A
/// creator can set a pipe's owner only to a SID in its own token, so the owner shows the daemon
/// ran as SYSTEM, the tearmesh service account or an elevated Administrator. LocalService and
/// NetworkService aren't trusted: many unrelated services run as them. (The server process's
/// token would say the same, but ordinary users may not open it.)
fn verify_server(pipe: &NamedPipeClient) -> Result<()> {
    let (mut owner, mut sd) = (null_mut(), null_mut());
    let err = unsafe {
        GetSecurityInfo(
            pipe.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    ensure!(
        err == 0,
        "reading the pipe's owner: {}",
        io::Error::from_raw_os_error(err as i32)
    );
    let _sd = Local(sd);
    let owner = sid_string(owner)?;
    let trusted = [SYSTEM, ADMINISTRATORS].contains(&owner.as_str())
        || user_identity(SERVICE_ACCOUNT).is_ok_and(|s| s == owner);
    ensure!(
        trusted,
        "the pipe belongs to {owner}, not the tear-mesh service: another program may have taken its name"
    );
    Ok(())
}

/// The account's SID. Takes `name`, `MACHINE\name` or `NT SERVICE\name`.
pub fn user_identity(name: &str) -> Result<String> {
    let w = wide(name);
    let (mut n, mut d, mut kind) = (0u32, 0u32, 0);
    unsafe {
        LookupAccountNameW(
            null(),
            w.as_ptr(),
            null_mut(),
            &mut n,
            null_mut(),
            &mut d,
            &mut kind,
        )
    };
    ensure!(n > 0, "no such account: {}", io::Error::last_os_error());
    let mut sid = vec![0u32; (n as usize).div_ceil(4)];
    let mut domain = vec![0u16; d as usize];
    check(
        unsafe {
            LookupAccountNameW(
                null(),
                w.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut n,
                domain.as_mut_ptr(),
                &mut d,
                &mut kind,
            )
        },
        "looking up the account",
    )?;
    sid_string(sid.as_mut_ptr().cast())
}

pub fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default()
}

/// Write-then-rename with fsync, so a crash leaves the old file or the new one. The file takes
/// its directory's ACL, which `secure_dir` makes private.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// The daemon's state directory: SYSTEM, Administrators and the daemon's user only, nothing
/// inherited from the parent, and the same for everything inside.
pub fn secure_dir(dir: &Path) -> Result<()> {
    let me = process_user()?;
    let sd = security_descriptor(&format!(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})"
    ))?;
    let (mut present, mut dacl, mut defaulted) = (0, null_mut(), 0);
    check(
        unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) },
        "reading the new ACL",
    )?;
    let err = unsafe {
        SetNamedSecurityInfoW(
            wide(dir).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    ensure!(
        err == 0,
        "securing {}: {}",
        dir.display(),
        io::Error::from_raw_os_error(err as i32)
    );
    Ok(())
}

/// Starts `command` as `user` with runas, which asks for the user's password and opens a new
/// window. runas can't pass environment variables, so it runs `tearmesh env-run` to set them.
pub fn launch(user: &str, env: &[(String, String)], command: &[String]) -> Result<()> {
    let mut args = vec![
        std::env::current_exe()?.display().to_string(),
        "env-run".into(),
    ];
    for (k, v) in env {
        args.extend(["--set".into(), format!("{k}={v}")]);
    }
    args.push("--".into());
    args.extend_from_slice(command);
    let line: Vec<String> = args.iter().map(|a| quote(a)).collect();
    let ok = std::process::Command::new("runas")
        .arg(format!("/user:{user}"))
        .arg(line.join(" "))
        .status()
        .context("running runas")?
        .success();
    ensure!(ok, "runas failed");
    Ok(())
}

/// One argument of a command line, quoted so the Microsoft C runtime parses it back unchanged.
fn quote(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return a.into();
    }
    let mut out = String::from('"');
    let mut slashes = 0;
    for c in a.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        // Backslashes are literal unless a quote follows: then they double and the quote escapes.
        let n = if c == '"' { slashes * 2 + 1 } else { slashes };
        out.extend(std::iter::repeat_n('\\', n));
        out.push(c);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    out
}

/// Resolves on Ctrl-C, the console closing, or system shutdown.
pub async fn shutdown_signal() -> Result<()> {
    use tokio::signal::windows::{ctrl_c, ctrl_close, ctrl_shutdown};
    let (mut c, mut close, mut shut) = (ctrl_c()?, ctrl_close()?, ctrl_shutdown()?);
    tokio::select! {
        _ = c.recv() => {}
        _ = close.recv() => {}
        _ = shut.recv() => {}
    }
    Ok(())
}

static SERVICE_CONFIG: OnceLock<Config> = OnceLock::new();
windows_service::define_windows_service!(ffi_service_main, service_main);

/// Runs the daemon under the service manager. A service's stderr goes nowhere, so it logs to
/// `daemon.log` in the state directory.
pub fn run_service(config: PathBuf) -> Result<()> {
    let cfg = Config::load(&config)?;
    std::fs::create_dir_all(&cfg.state_dir)?;
    // shortcut: the log is never rotated; add rotation if long-running nodes fill disks.
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(cfg.state_dir.join("daemon.log"))?;
    tracing_subscriber::fmt()
        .with_writer(std::sync::Mutex::new(log))
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,iroh=warn,noq=warn".into()),
        )
        .init();
    let _ = SERVICE_CONFIG.set(cfg);
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connecting to the service manager (--service is for the tearmesh service)")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = serve_service() {
        tracing::error!("service: {e:#}");
    }
}

fn serve_service() -> Result<()> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut stop_tx = Some(stop_tx);
    let status = service_control_handler::register(SERVICE_NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Some(tx) = stop_tx.take() {
                let _ = tx.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |current_state, controls_accepted, exit_code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        })
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::NO_ERROR,
    )?;
    let cfg = SERVICE_CONFIG.get().context("no config")?.clone();
    let r = tokio::runtime::Runtime::new()?.block_on(async move {
        let node = crate::node::Node::start(cfg).await?;
        let server = tokio::spawn(crate::ipc::serve(node.clone()));
        let r = tokio::select! {
            r = server => r.map_err(anyhow::Error::from).and_then(|r| r),
            _ = stop_rx => Ok(()),
        };
        node.shutdown().await;
        r
    });
    let code = match &r {
        Ok(()) => ServiceExitCode::NO_ERROR,
        Err(e) => {
            tracing::error!("daemon: {e:#}");
            ServiceExitCode::ServiceSpecific(1)
        }
    };
    report(ServiceState::Stopped, ServiceControlAccept::empty(), code)?;
    Ok(())
}

/// Memory from LocalAlloc (security descriptors, SIDs, SID strings), freed on drop.
struct Local(*mut c_void);

// SAFETY: only read after it's built.
unsafe impl Send for Local {}
unsafe impl Sync for Local {}

impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

fn security_descriptor(sddl: &str) -> Result<Local> {
    let mut sd = null_mut();
    check(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        },
        "building a security descriptor",
    )?;
    Ok(Local(sd))
}

fn is_member(token: HANDLE, sid: &str) -> Result<bool> {
    let mut p = null_mut();
    check(
        unsafe { ConvertStringSidToSidW(wide(sid).as_ptr(), &mut p) },
        "parsing a SID",
    )?;
    let p = Local(p);
    let mut yes = 0;
    check(
        unsafe { CheckTokenMembership(token, p.0, &mut yes) },
        "checking group membership",
    )?;
    Ok(yes != 0)
}

fn token_user(token: HANDLE) -> Result<String> {
    let mut len = 0;
    unsafe { GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    check(
        unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) },
        "reading a token's user",
    )?;
    sid_string(unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}

fn process_user() -> Result<String> {
    let mut t = null_mut();
    check(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) },
        "opening this process's token",
    )?;
    let t = unsafe { OwnedHandle::from_raw_handle(t) };
    token_user(t.as_raw_handle())
}

fn sid_string(sid: PSID) -> Result<String> {
    let mut s = null_mut();
    check(
        unsafe { ConvertSidToStringSidW(sid, &mut s) },
        "formatting a SID",
    )?;
    let _s = Local(s.cast());
    let len = (0..).take_while(|&i| unsafe { *s.add(i) } != 0).count();
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(s, len)
    }))
}

fn check(ok: BOOL, what: &str) -> Result<()> {
    if ok == 0 {
        bail!("{what}: {}", io::Error::last_os_error());
    }
    Ok(())
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(r"\\.\pipe\tearmesh"), r"\\.\pipe\tearmesh");
        assert_eq!(quote(""), r#""""#);
        assert_eq!(
            quote(r"C:\Program Files\x.exe"),
            r#""C:\Program Files\x.exe""#
        );
        assert_eq!(quote(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote(r"dir with space\"), r#""dir with space\\""#);
        assert_eq!(quote(r#"a\"b"#), r#""a\\\"b""#);
    }

    #[test]
    fn identities() {
        assert_eq!(user_identity("SYSTEM").unwrap(), SYSTEM);
        assert_eq!(
            user_identity(r"NT AUTHORITY\LOCAL SERVICE").unwrap(),
            LOCAL_SERVICE
        );
        assert_eq!(user_identity("Administrators").unwrap(), ADMINISTRATORS);
        assert!(user_identity("no-such-user-tearmesh").is_err());
        assert!(process_user().unwrap().starts_with("S-1-5-"));
    }

    /// Needs an elevated Administrator or SYSTEM.
    #[tokio::test]
    async fn pipe_identifies_the_caller() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let path = PathBuf::from(format!(r"\\.\pipe\tearmesh-test-{}", std::process::id()));
        let l = listen(&path).await.unwrap();
        assert!(
            listen(&path).await.is_err(),
            "a second server on the name must fail"
        );
        let p = path.clone();
        let c = tokio::spawn(async move {
            let (r, mut w) = connect(&p).await.unwrap();
            w.write_all(b"hello\n").await.unwrap();
            let mut line = String::new();
            BufReader::new(r).read_line(&mut line).await.unwrap();
            line
        });
        let mut inc = tokio::time::timeout(Duration::from_secs(10), l.accept())
            .await
            .expect("no client connected")
            .unwrap();
        let mut reader = BufReader::new(inc.read);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "hello\n");
        let who = (inc.caller)().unwrap();
        assert_eq!(who.id, process_user().unwrap());
        assert!(who.admin);
        inc.write.write_all(b"back\n").await.unwrap();
        assert_eq!(c.await.unwrap(), "back\n");
        // The thread that identified the client isn't left impersonating it.
        let mut t = null_mut();
        assert_eq!(
            unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut t) },
            0
        );
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(windows_sys::Win32::Foundation::ERROR_NO_TOKEN as i32)
        );
    }

    /// A UAC-filtered token holds Administrators as deny-only. Built here from this process's
    /// token, at identification level as the daemon sees a client. Needs an elevated process.
    #[test]
    fn deny_only_administrators_isnt_admin() {
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DuplicateToken, SID_AND_ATTRIBUTES, SecurityIdentification,
            TOKEN_DUPLICATE,
        };
        let ident = |t: HANDLE| {
            let mut i = null_mut();
            check(
                unsafe { DuplicateToken(t, SecurityIdentification, &mut i) },
                "dup",
            )
            .unwrap();
            unsafe { OwnedHandle::from_raw_handle(i) }
        };
        let mut t = null_mut();
        let access = TOKEN_DUPLICATE | TOKEN_QUERY;
        check(
            unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut t) },
            "open",
        )
        .unwrap();
        let t = unsafe { OwnedHandle::from_raw_handle(t) };
        let mut ba = null_mut();
        check(
            unsafe { ConvertStringSidToSidW(wide(ADMINISTRATORS).as_ptr(), &mut ba) },
            "sid",
        )
        .unwrap();
        let ba = Local(ba);
        let disable = SID_AND_ATTRIBUTES {
            Sid: ba.0,
            Attributes: 0,
        };
        let mut r = null_mut();
        check(
            unsafe {
                CreateRestrictedToken(
                    t.as_raw_handle(),
                    0,
                    1,
                    &disable,
                    0,
                    null(),
                    0,
                    null(),
                    &mut r,
                )
            },
            "restrict",
        )
        .unwrap();
        let r = unsafe { OwnedHandle::from_raw_handle(r) };
        assert!(is_member(ident(t.as_raw_handle()).as_raw_handle(), ADMINISTRATORS).unwrap());
        assert!(!is_member(ident(r.as_raw_handle()).as_raw_handle(), ADMINISTRATORS).unwrap());
    }

    #[test]
    fn private_dir() {
        let d = tempfile::tempdir().unwrap();
        secure_dir(d.path()).unwrap();
        write_private(&d.path().join("k"), b"secret").unwrap();
        assert_eq!(std::fs::read(d.path().join("k")).unwrap(), b"secret");
    }
}
