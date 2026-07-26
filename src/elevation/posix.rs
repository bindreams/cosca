//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, non-destructive command rewrite, and the controlling-terminal probe.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::plan::{BackendSet, Host, Os};
use super::{Auth, Backend};
use crate::error::Error;

/// A valid environment variable name: `[A-Za-z_][A-Za-z0-9_]*`, ASCII only. A name
/// with a comma / `=` / non-ASCII byte has no lossless place in `--preserve-env`'s
/// comma-joined list or `--setenv=NAME=VALUE`.
fn valid_env_name(k: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let b = k.as_bytes();
    match b.first() {
        Some(&c) if c == b'_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    b.iter().all(|&c| c == b'_' || c.is_ascii_alphanumeric())
}

fn unsupported_env_name(k: &OsStr) -> Error {
    Error::Unsupported {
        op: "forwarding an env var with an unusual name across elevation".into(),
        platform: "unix",
        detail: format!("env var name {k:?} is not [A-Za-z_][A-Za-z0-9_]*; it cannot be forwarded losslessly"),
    }
}

/// `--preserve-env=A,B,…` (names validated; values are set in the backend's own env).
fn preserve_env_flag(env: &[(OsString, OsString)]) -> Result<OsString, Error> {
    let mut flag = OsString::from("--preserve-env=");
    for (i, (k, _)) in env.iter().enumerate() {
        if !valid_env_name(k) {
            return Err(unsupported_env_name(k));
        }
        if i > 0 {
            flag.push(",");
        }
        flag.push(k);
    }
    Ok(flag)
}

/// Build the full elevated argv. argv[0] is the injected ABSOLUTE `backend_path`.
/// `env` MUST be pre-sanitized and sorted (see [`super::sanitize::EnvSanitizer::apply`]).
/// Pure — no installed backend required.
// Not yet called by production code: the sync/async POSIX spawn arms that invoke this
// land in later tasks of the elevation plan.
#[allow(dead_code)]
pub(crate) fn build_argv(
    backend: Backend,
    backend_path: &OsStr,
    auth: &Auth,
    program: &OsStr,
    args: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<Vec<OsString>, Error> {
    let mut argv: Vec<OsString> = vec![backend_path.to_os_string()];
    match backend {
        Backend::Sudo => {
            match auth {
                Auth::NonInteractive => argv.push("-n".into()),
                Auth::Stdin(_) => argv.push("-S".into()),
                Auth::Askpass(_) => argv.push("-A".into()),
                Auth::Interactive | Auth::Gui => {}
            }
            if !env.is_empty() {
                argv.push(preserve_env_flag(env)?);
            }
        }
        Backend::Doas => {
            debug_assert!(env.is_empty(), "doas forwards no env; the rewrite rejects .env() for doas");
            if matches!(auth, Auth::NonInteractive) {
                argv.push("-n".into());
            }
        }
        Backend::Pkexec => {
            debug_assert!(env.is_empty(), "pkexec forwards no env; the rewrite rejects .env() for pkexec");
            // Fail loud if the graphical agent is missing, instead of a blocking text prompt.
            argv.push("--disable-internal-agent".into());
            // pkexec has no `--` terminator, so a leading-dash program cannot be shielded.
            if program_starts_with_dash(program) {
                return Err(Error::Unsupported {
                    op: "elevating a leading-dash program under pkexec".into(),
                    platform: "unix",
                    detail: "pkexec cannot parse a `--` terminator, so a program starting with `-` would be taken as a pkexec option; use sudo/doas/run0, or a non-dash program path".into(),
                });
            }
        }
        Backend::Run0 => {
            argv.push("--pipe".into());
            if matches!(auth, Auth::NonInteractive) {
                argv.push("--no-ask-password".into());
            }
            for (k, v) in env {
                if !valid_env_name(k) {
                    return Err(unsupported_env_name(k));
                }
                let mut a = OsString::from("--setenv=");
                a.push(k);
                a.push("=");
                a.push(v);
                argv.push(a);
            }
        }
        Backend::Auto => unreachable!("build_argv received unresolved Backend::Auto; the planner resolves Auto"),
    }
    // Terminate option/assignment parsing before the program — every backend EXCEPT
    // pkexec, whose option loop mis-parses `--` (a leading-dash pkexec program is
    // rejected above instead).
    if backend != Backend::Pkexec {
        argv.push("--".into());
    }
    argv.push(program.to_os_string());
    argv.extend(args.iter().cloned());
    Ok(argv)
}

/// Does `program` begin with `-`? (Only pkexec, which has no `--` shield, cares.)
fn program_starts_with_dash(program: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;
    program.as_bytes().first() == Some(&b'-')
}

pub(super) fn is_elevated() -> bool {
    // SAFETY: geteuid has no preconditions and never fails.
    unsafe { libc::geteuid() == 0 }
}

/// Does this session have a controlling terminal? Probes `/dev/tty` directly —
/// which resolves to the controlling terminal regardless of stdin redirection and
/// fails once a process has none (e.g. after `setsid`). `O_NONBLOCK` avoids
/// blocking on a carrier-less serial console; the probe only needs the open to
/// succeed. `isatty(stdin)` answers a different question and is wrong for both cases.
#[doc(hidden)]
pub fn controlling_terminal_present() -> bool {
    // SAFETY: open/close of a fixed path; the fd is closed on the success path.
    unsafe {
        let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK);
        if fd < 0 {
            return false;
        }
        libc::close(fd);
        true
    }
}

/// A best-effort HINT that `path` is an executable file for the EFFECTIVE ids.
/// `faccessat(AT_EACCESS)` answers for the ids that will actually exec (unlike
/// `access`, which uses the real ids); a real exec failure is still surfaced as
/// `BackendUnavailable` at spawn time.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: faccessat with a valid NUL-terminated path; a read-only permission query.
    path.is_file()
        && unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

/// Resolve `program` to its ABSOLUTE path on `$PATH`.
pub(super) fn resolve_on_path(program: &str) -> Option<PathBuf> {
    resolve_in_path_var(&std::env::var_os("PATH")?, program)
}

/// PURE path resolution over an explicit PATH value: check the exec bit and SKIP
/// empty elements (an empty element is CWD — never resolve a backend there).
pub(super) fn resolve_in_path_var(path_var: &OsStr, program: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var).find_map(|dir| {
        if dir.as_os_str().is_empty() {
            return None; // empty element = CWD; never resolve here
        }
        let cand = dir.join(program);
        is_executable(&cand).then_some(cand)
    })
}

pub(super) fn detect() -> Host {
    Host {
        elevated: is_elevated(),
        has_tty: controlling_terminal_present(),
        available: BackendSet {
            run0: resolve_on_path("run0"),
            sudo: resolve_on_path("sudo"),
            doas: resolve_on_path("doas"),
            pkexec: resolve_on_path("pkexec"),
        },
        os: Os::Unix,
    }
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
