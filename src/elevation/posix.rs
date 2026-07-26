//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, non-destructive command rewrite, and the controlling-terminal probe.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use super::plan::{BackendSet, Host, Os, Transition};
use super::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, Privilege, Secret};
use crate::command::{Command, CommandInput, EnvOp};
use crate::error::{ElevationErrorKind, Error};
use crate::stdio::{Fd, Stdio};

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
            debug_assert!(
                env.is_empty(),
                "doas forwards no env; the rewrite rejects .env() for doas"
            );
            if matches!(auth, Auth::NonInteractive) {
                argv.push("-n".into());
            }
        }
        Backend::Pkexec => {
            debug_assert!(
                env.is_empty(),
                "pkexec forwards no env; the rewrite rejects .env() for pkexec"
            );
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
    path.is_file() && unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
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

// ===== Non-destructive rewrite + deferred password channel =====
//
// The deferred-password chain (`PendingPassword`/`password_line`/`write_*`) and the
// `PosixRewrite` fields are consumed by the sync POSIX spawn arm
// (`crate::child::spawn::spawn`); the async arm follows in a later task.

/// The `Auth::Stdin` password channel: the pipe write-end plus the secret, written
/// AFTER spawn (the child is then draining via `sudo -S`).
pub(crate) struct PendingPassword {
    writer: std::io::PipeWriter,
    secret: Secret,
}

/// The password line to feed `sudo -S`: the secret plus a trailing newline, in a buffer
/// pre-sized to `secret.len() + 1` so the `push` never reallocates. A realloc would leave
/// an un-zeroized plaintext copy in the freed allocation. Zeroize the returned buffer
/// after use.
fn password_line(secret: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(secret.len() + 1);
    bytes.extend_from_slice(secret);
    bytes.push(b'\n');
    bytes
}

/// Put `writer`'s underlying fd into non-blocking mode so a write cannot block when the
/// backend never reads fd0 (a cached-credential / NOPASSWD sudo). The non-blocking
/// invariant is load-bearing (`write_after_spawn` relies on `WouldBlock`), so an fcntl
/// failure is surfaced via `log::warn!`, never silently swallowed.
fn set_writer_nonblocking(writer: &std::io::PipeWriter) {
    use std::os::fd::AsRawFd;
    let fd = writer.as_raw_fd();
    // SAFETY: fcntl on a live owned fd; F_GETFL/F_SETFL take/return the flag word.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            log::warn!(
                "could not read the password channel's flags (F_GETFL): {}; leaving it blocking",
                std::io::Error::last_os_error()
            );
            return;
        }
        if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            log::warn!(
                "could not set the password channel non-blocking (F_SETFL): {}; leaving it blocking",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Block until `fd` is writable, or report that the reader hung up. The `-1` timeout is a
/// real readiness wait on a genuine fd event (no time-based polling). `Ok(true)` =
/// writable, `Ok(false)` = the reader closed / errored (`POLLHUP`/`POLLERR`).
fn wait_writable(fd: std::os::fd::RawFd) -> Result<bool, std::io::Error> {
    loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        // SAFETY: one initialized pollfd; `-1` blocks until a readiness event.
        let rc = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, -1) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: reissue the wait (no arbitrary retry bound)
            }
            return Err(err);
        }
        if pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            return Ok(false);
        }
        if pfd.revents & libc::POLLOUT != 0 {
            return Ok(true);
        }
    }
}

fn auth_failed(detail: String) -> Error {
    Error::Elevation {
        kind: ElevationErrorKind::AuthFailed,
        detail,
    }
}

/// Write `bytes` to the non-blocking `writer` with a `write()` LOOP (never `write_all`,
/// which can return `WouldBlock` AFTER a partial write and truncate the password). A
/// WouldBlock/BrokenPipe with ZERO bytes written means the backend never read fd0
/// (cached credentials) → success; the SAME error after a partial write is a real
/// truncation → `AuthFailed`.
fn write_password_bytes(writer: &mut std::io::PipeWriter, fd: std::os::fd::RawFd, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut written = 0usize;
    while written < bytes.len() {
        match writer.write(&bytes[written..]) {
            Ok(0) => {
                return if written == 0 {
                    log::debug!("elevation backend did not consume the password (fd0 accepted nothing)");
                    Ok(())
                } else {
                    Err(auth_failed(
                        "elevation backend closed the password channel after a partial write".into(),
                    ))
                };
            }
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if written == 0 {
                    log::debug!("elevation backend did not consume the password (fd0 would block, no read): {e}");
                    return Ok(());
                }
                match wait_writable(fd) {
                    Ok(true) => continue,
                    Ok(false) => {
                        return Err(auth_failed(
                            "elevation backend closed fd0 after a partial password write".into(),
                        ))
                    }
                    Err(pe) => {
                        return Err(auth_failed(format!(
                            "waiting to deliver the sudo -S password failed: {pe}"
                        )))
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                if written == 0 {
                    log::debug!("elevation backend did not consume the password (fd0 closed / EPIPE): {e}");
                    return Ok(());
                }
                return Err(auth_failed(format!(
                    "elevation backend closed fd0 after a partial password write: {e}"
                )));
            }
            Err(e) => return Err(auth_failed(format!("could not deliver the sudo -S password: {e}"))),
        }
    }
    Ok(())
}

impl PendingPassword {
    /// Deliver the password + newline, then EOF. RACE-HARDENED: a cached-credential /
    /// NOPASSWD sudo never reads fd0, so the writer is non-blocking and a `BrokenPipe`
    /// (`EPIPE`) or `WouldBlock` with nothing yet written means "the backend did not need
    /// the password" → `log::debug!` + `Ok`, NOT `AuthFailed`. The buffer is zeroized and
    /// the writer dropped (EOF) on EVERY path. On a genuine failure the CALLER (the spawn
    /// arm) kills and reaps the running child.
    pub(crate) fn write_after_spawn(mut self) -> Result<(), Error> {
        use std::os::fd::AsRawFd;
        let mut bytes = password_line(self.secret.expose());
        set_writer_nonblocking(&self.writer);
        let fd = self.writer.as_raw_fd();
        let result = write_password_bytes(&mut self.writer, fd, &bytes);
        bytes.zeroize();
        drop(self.writer); // EOF after the password line
        result
    }
}

/// Outcome of a POSIX rewrite. `derived` is the command to spawn (the backend wrapper, or
/// — when already elevated — the sanitized original). `report` is attached to the
/// resulting `Child`. `password_write` is delivered after spawn. `backend_path` is the
/// resolved argv[0] the spawn arm passes to `remap_derived_spawn_error` (`None` when no
/// backend wraps the child, i.e. already elevated).
pub(crate) struct PosixRewrite {
    pub derived: Option<Command>,
    pub report: Option<ElevationReport>,
    pub password_write: Option<PendingPassword>,
    pub backend_path: Option<PathBuf>,
}

/// Collect the explicitly-`Set` env into an ordered (k,v) list (later `Set`s win).
/// `Remove`/`Clear` are rejected before this runs, so only `Set` survives.
fn explicit_set_env(ops: &[EnvOp]) -> Vec<(OsString, OsString)> {
    let mut map: std::collections::BTreeMap<OsString, OsString> = std::collections::BTreeMap::new();
    for op in ops {
        if let EnvOp::Set(k, v) = op {
            map.insert(k.clone(), v.clone());
        }
    }
    map.into_iter().collect()
}

/// Program + args, honoring `executable()`. An argv[0] distinct from a set
/// `executable()` cannot survive the backend wrapper → `Unsupported`.
fn program_and_args(cmd: &Command) -> Result<(OsString, Vec<OsString>), Error> {
    let CommandInput::Argv(argv) = cmd.input() else {
        return Err(Error::Unsupported {
            op: "elevation of a commandline() command".into(),
            platform: "unix",
            detail:
                "elevation requires an argv command (set .args([...])); a raw command line cannot be safely wrapped"
                    .into(),
        });
    };
    if argv.is_empty() {
        return Err(Error::Unsupported {
            op: "elevation of an empty command".into(),
            platform: "unix",
            detail: "set a program via .args([...]) before .elevate()".into(),
        });
    }
    match cmd.executable_path() {
        Some(exe) => {
            if argv[0].as_os_str() != exe.as_os_str() {
                return Err(Error::Unsupported {
                    op: "elevation with an argv[0] distinct from executable()".into(),
                    platform: "unix",
                    detail: "the backend runs the loaded file with argv[0] = its path; a separate argv[0] cannot survive elevation".into(),
                });
            }
            Ok((exe.as_os_str().to_os_string(), argv[1..].to_vec()))
        }
        None => Ok((argv[0].clone(), argv[1..].to_vec())),
    }
}

/// Structural request-validation, evaluated against the REQUESTED backend so the verdict
/// is privilege-independent. Run BEFORE the already-elevated short-circuit, so an
/// already-elevated caller gets the same rejection. (Backend availability + NoTty are
/// environmental and stay in the planner, after the short-circuit.)
fn reject_structural_posix_config(cmd: &Command, backend: Backend, auth: &Auth) -> Result<(), Error> {
    // commandline() / empty / distinct-argv0.
    program_and_args(cmd)?;
    if cmd.fds().keys().any(|f| f.raw() >= 3) {
        return Err(Error::Unsupported {
            op: "fd >= 3 on an elevated POSIX child".into(),
            platform: "unix",
            detail: "sudo/pkexec closefrom and run0's PID-1 reparent drop fds > 2; fd >= 3 needs the (deferred) broker"
                .into(),
        });
    }
    let ops = cmd.env_ops();
    if ops.iter().any(|o| matches!(o, EnvOp::Remove(_) | EnvOp::Clear)) {
        return Err(Error::Unsupported {
            op: ".env_remove()/.env_clear() + elevate".into(),
            platform: "unix",
            detail: "the backend builds the elevated base environment; the crate can add but not subtract from it"
                .into(),
        });
    }
    if ops.iter().any(|o| matches!(o, EnvOp::Set(..))) && matches!(backend, Backend::Doas | Backend::Pkexec) {
        return Err(Error::Unsupported {
            op: format!(".env() + Backend::{backend:?}"),
            platform: "unix",
            detail: "doas and pkexec expose no environment-forwarding mechanism; .env()/.envs() cannot cross them"
                .into(),
        });
    }
    if backend == Backend::Run0 && cmd.contain_request().mode.is_some() {
        return Err(Error::Unsupported {
            op: ".contain() + Backend::Run0".into(),
            platform: "unix",
            detail:
                "run0 runs the target as a PID 1-parented transient unit outside our cgroup; containment cannot span it"
                    .into(),
        });
    }
    if matches!(auth, Auth::Stdin(_)) && cmd.fds().contains_key(&Fd::STDIN) {
        return Err(Error::Unsupported {
            op: "Auth::Stdin with a caller-configured stdin".into(),
            platform: "unix",
            detail: "Auth::Stdin consumes fd0 to feed sudo -S the password; do not also configure stdin".into(),
        });
    }
    Ok(())
}

/// Transfer the caller's cwd / containment / kill-on-drop onto the derived command.
fn transfer_process_attrs(derived: &mut Command, cmd: &Command) {
    if let Some(d) = cmd.cwd() {
        derived.current_dir(d);
    }
    derived.set_contain(cmd.contain_request());
    derived.kill_on_drop(cmd.kill_on_drop_flag());
}

/// Detect-then-plan-then-rewrite. Thin wrapper over the pure form.
// Consumed by the sync POSIX spawn arm (`crate::child::spawn::spawn`); the pure
// `rewrite_with_host` is what the tests drive directly.
pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error> {
    rewrite_with_host(cmd, &Host::detect())
}

/// PURE given `host`: gate + plan + sanitize + build a DERIVED command. The caller's
/// `Command` `input`/`env_ops` are left untouched (non-destructive): the caller's fd 0-2
/// stdio is MOVED into the derived command (`ResolvedStdio::File` is not `Clone`).
pub(crate) fn rewrite_with_host(cmd: &mut Command, host: &Host) -> Result<PosixRewrite, Error> {
    let requested_backend = cmd.elevation_request().backend;
    let requested_auth = cmd.elevation_request().auth.clone();

    // Structural config gates FIRST — privilege-independent (before the short-circuit).
    reject_structural_posix_config(cmd, requested_backend, &requested_auth)?;

    match host.plan(Privilege::Elevated, requested_backend, requested_auth) {
        Transition::Reject { error } => Err(error),
        Transition::ElevateWindows { .. } => unreachable!("planner never yields ElevateWindows on a unix host"),
        Transition::RunAsIs => {
            // Already elevated: no wrapper, but the sanitizer STILL runs so a dangerous
            // forwarded var never reaches the root child. Build a non-destructive derived
            // command (the ORIGINAL program + args, sanitized env, fds MOVED).
            let (kept, stripped) = cmd.elevation_request().sanitizer.apply(explicit_set_env(cmd.env_ops()));
            let (program, args) = program_and_args(cmd)?;
            let mut argv = Vec::with_capacity(args.len() + 1);
            argv.push(program);
            argv.extend(args);
            let env_ops: Vec<EnvOp> = kept.iter().map(|(k, v)| EnvOp::Set(k.clone(), v.clone())).collect();
            let mut derived = Command::new();
            derived.set_input_argv(argv);
            derived.set_env_ops(env_ops);
            transfer_process_attrs(&mut derived, cmd);
            for (slot, resolved) in std::mem::take(cmd.fds_mut()) {
                derived.fds_mut().insert(slot, resolved);
            }
            Ok(PosixRewrite {
                derived: Some(derived),
                report: Some(ElevationReport {
                    via: ElevatedVia::AlreadyElevated,
                    stripped_env: stripped,
                    stdio: ElevatedStdio::Passthrough,
                }),
                password_write: None,
                backend_path: None,
            })
        }
        Transition::ElevatePosix { backend, path, auth } => {
            let (kept, stripped) = cmd.elevation_request().sanitizer.apply(explicit_set_env(cmd.env_ops()));
            // Backend resolved via Auto may land on a non-sudo target that cannot forward
            // env (the requested-backend gate only catches the EXPLICIT doas/pkexec case).
            if !kept.is_empty() && matches!(backend, Backend::Doas | Backend::Pkexec) {
                return Err(Error::Unsupported {
                    op: format!(".env() + Backend::{backend:?} (resolved via Auto)"),
                    platform: "unix",
                    detail:
                        "doas and pkexec expose no environment-forwarding mechanism; .env()/.envs() cannot cross them"
                            .into(),
                });
            }
            let (program, args) = program_and_args(cmd)?;
            let argv = build_argv(backend, path.as_os_str(), &auth, &program, &args, &kept)?;

            // --- build the DERIVED command (the caller's Command stays intact) ---
            let mut new_ops: Vec<EnvOp> = Vec::new();
            if backend == Backend::Sudo {
                // sudo preserves these from its OWN env (named in --preserve-env); run0
                // carried them in argv already; doas/pkexec were rejected above.
                for (k, v) in &kept {
                    new_ops.push(EnvOp::Set(k.clone(), v.clone()));
                }
            }
            if let Auth::Askpass(p) = &auth {
                new_ops.push(EnvOp::Set(OsString::from("SUDO_ASKPASS"), p.as_os_str().to_os_string()));
            }
            let mut derived = Command::new();
            derived.set_input_argv(argv);
            derived.set_env_ops(new_ops);
            transfer_process_attrs(&mut derived, cmd);

            // Auth::Stdin: wire the derived fd0 to a fresh pipe's read end; the password is
            // written after spawn (the fd0 conflict was rejected in the structural gate).
            let mut password_write = None;
            if let Auth::Stdin(secret) = &auth {
                let (reader, writer) = std::io::pipe().map_err(Error::Io)?;
                let reader_file = File::from(OwnedFd::from(reader));
                derived.stdin(Stdio::from_file(reader_file))?;
                password_write = Some(PendingPassword {
                    writer,
                    secret: secret.clone(),
                });
            }

            // Move the caller's fd 0-2 stdio into the derived command (File is not Clone).
            // Skip fd0 when Auth::Stdin already wired it to the pipe read end.
            for (slot, resolved) in std::mem::take(cmd.fds_mut()) {
                if password_write.is_some() && slot == Fd::STDIN {
                    continue;
                }
                derived.fds_mut().insert(slot, resolved);
            }

            let stdio = if matches!(auth, Auth::Stdin(_)) {
                ElevatedStdio::StdinConsumed
            } else {
                ElevatedStdio::Passthrough
            };
            Ok(PosixRewrite {
                derived: Some(derived),
                report: Some(ElevationReport {
                    via: ElevatedVia::Wrapped(backend),
                    stripped_env: stripped,
                    stdio,
                }),
                password_write,
                backend_path: Some(path),
            })
        }
    }
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
