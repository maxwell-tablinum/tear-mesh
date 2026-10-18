//! What differs between operating systems: the local socket and who is calling on it, OS user
//! lookups, private files, launching a command as a boundary's user, and shutdown signals.
//! Everything else in tear-mesh is the same code on every OS.

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::*;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

pub type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
pub type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Who is on the other end of a local connection, as the OS reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct Caller {
    /// A uid (Unix) or a SID (Windows), in the same form `user_identity` returns.
    pub id: String,
    /// root, an elevated Administrator, SYSTEM, or the daemon's own user.
    pub admin: bool,
}

/// An accepted local connection. `caller` may only be called after the first line has been
/// read: Windows identifies a pipe client by the last message read from it.
pub struct Incoming {
    pub read: BoxRead,
    pub write: BoxWrite,
    pub caller: Box<dyn FnMut() -> anyhow::Result<Caller> + Send>,
}
