//! The `setuid-stdin-block <mode>` mode: run from a setuid-root copy of this binary, so at start
//! the real uid is the caller's and the effective and saved uids are 0.
//!
//! It moves to the mode's uid triple, checks it, writes `+` on stdout, then reads one-byte
//! commands from stdin and acknowledges each with one byte, only after its syscall succeeded.
//! A failed check or syscall writes nothing to stdout, names the mismatch on stderr and exits 3;
//! EOF on stdin exits 0.
//!
//! | mode | Linux `setresuid` | macOS |
//! |---|---|---|
//! | `root` | (0, 0, 0) | `setuid(0)` |
//! | `permitted` | (caller, caller, 0) | exit 3 |
//! | `euid-only` | (caller, 0, caller) | exit 3 |
//! | `suid-only` | (0, 0, caller) | exit 3 |
//!
//! | cmd | Linux syscall (macOS exits 3) | ack |
//! |---|---|---|
//! | `d` | `setresuid(caller, caller, 0)` | `D` |
//! | `r` | `setresuid(0, 0, 0)` | `R` |
//! | `n` | `unshare(CLONE_NEWUSER)` | `N` |
//!
//! After `n` the process is in a new user namespace that maps no uid, so every credential command
//! (`d`, `r`) fails with `EINVAL` and exits 3. `n` is consumed by the credential-flip proofs that
//! run a child inside a user namespace.
//!
//! Every failure, I/O included, exits 3 through [`die`]. [`provision`] is also the startup check of
//! `setuid-control-block`, so one provisioning contract exists.

use std::io::{Read, Write};
use std::process::exit;

fn die(msg: &str) -> ! {
    eprintln!("setuid-stdin-block: {msg}");
    exit(3)
}

/// Checks the start state and moves to `mode`'s uid triple; returns the caller's uid. The error
/// names the mismatch.
pub fn provision(mode: &str) -> Result<libc::uid_t, String> {
    let caller = start()?;
    set_mode(mode, caller)?;
    Ok(caller)
}

pub fn run(args: &[String]) {
    let mode = args.get(2).map(String::as_str).unwrap_or_else(|| die("missing mode"));
    let caller = provision(mode).unwrap_or_else(|e| die(&e));
    let mut out = std::io::stdout();
    out.write_all(b"+")
        .and_then(|()| out.flush())
        .unwrap_or_else(|e| die(&format!("write the ready byte: {e}")));
    let mut cmd = [0u8; 1];
    let mut stdin = std::io::stdin();
    while stdin
        .read(&mut cmd)
        .unwrap_or_else(|e| die(&format!("read a command: {e}")))
        == 1
    {
        let ack = command(cmd[0], caller).unwrap_or_else(|e| die(&e));
        out.write_all(&[ack])
            .and_then(|()| out.flush())
            .unwrap_or_else(|e| die(&format!("write an ack: {e}")));
    }
}

#[cfg(target_os = "linux")]
fn ids() -> Result<(libc::uid_t, libc::uid_t, libc::uid_t), String> {
    let (mut r, mut e, mut s) = (0, 0, 0);
    // SAFETY: three valid out-pointers.
    if unsafe { libc::getresuid(&mut r, &mut e, &mut s) } != 0 {
        return Err(format!("getresuid: {}", std::io::Error::last_os_error()));
    }
    Ok((r, e, s))
}

#[cfg(target_os = "linux")]
fn setres(r: libc::uid_t, e: libc::uid_t, s: libc::uid_t) -> Result<(), String> {
    // SAFETY: `setresuid` has no memory preconditions.
    if unsafe { libc::setresuid(r, e, s) } != 0 {
        return Err(format!("setresuid({r}, {e}, {s}): {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// The caller's uid, after checking the start state (real = caller, effective = saved = 0).
#[cfg(target_os = "linux")]
fn start() -> Result<libc::uid_t, String> {
    let (r, e, s) = ids()?;
    if r == 0 || e != 0 || s != 0 {
        return Err(format!(
            "started with (ruid, euid, suid) = ({r}, {e}, {s}), expected (caller, 0, 0) with a non-root caller: the file is not setuid-root (wrong owner/mode or a nosuid mount), or the caller is root"
        ));
    }
    Ok(r)
}

#[cfg(target_os = "linux")]
fn set_mode(mode: &str, caller: libc::uid_t) -> Result<(), String> {
    let want = match mode {
        "root" => (0, 0, 0),
        "permitted" => (caller, caller, 0),
        "euid-only" => (caller, 0, caller),
        "suid-only" => (0, 0, caller),
        other => return Err(format!("unknown mode {other:?}")),
    };
    setres(want.0, want.1, want.2)?;
    let got = ids()?;
    if got != want {
        return Err(format!("mode {mode}: ids are {got:?}, expected {want:?}"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn command(cmd: u8, caller: libc::uid_t) -> Result<u8, String> {
    match cmd {
        b'd' => setres(caller, caller, 0).map(|()| b'D'),
        b'r' => setres(0, 0, 0).map(|()| b'R'),
        b'n' => {
            // SAFETY: `unshare` has no memory preconditions.
            if unsafe { libc::unshare(libc::CLONE_NEWUSER) } == 0 {
                Ok(b'N')
            } else {
                Err(format!("unshare(CLONE_NEWUSER): {}", std::io::Error::last_os_error()))
            }
        }
        other => Err(format!("unknown command {other:#x}")),
    }
}

/// macOS has no saved-uid triple to steer, so only `root` exists and no command does.
#[cfg(not(target_os = "linux"))]
fn start() -> Result<libc::uid_t, String> {
    // SAFETY: `getuid` and `geteuid` have no preconditions.
    let (r, e) = unsafe { (libc::getuid(), libc::geteuid()) };
    if r == 0 || e != 0 {
        return Err(format!(
            "started with (ruid, euid) = ({r}, {e}), expected (caller, 0) with a non-root caller: the file is not setuid-root (wrong owner/mode or a nosuid mount), or the caller is root"
        ));
    }
    Ok(r)
}

#[cfg(not(target_os = "linux"))]
fn set_mode(mode: &str, _caller: libc::uid_t) -> Result<(), String> {
    if mode != "root" {
        return Err(format!("mode {mode:?} exists only on Linux"));
    }
    // SAFETY: `setuid`, `getuid` and `geteuid` have no memory preconditions.
    let (rc, r, e) = unsafe { (libc::setuid(0), libc::getuid(), libc::geteuid()) };
    if rc != 0 || r != 0 || e != 0 {
        return Err(format!(
            "setuid(0) returned {rc}: {}; ids are (ruid, euid) = ({r}, {e}), expected (0, 0)",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn command(cmd: u8, _caller: libc::uid_t) -> Result<u8, String> {
    Err(format!("command {cmd:#x} exists only on Linux"))
}
