//! POSIX elevation effect layer (`cfg(unix)`): backend detection, pure argv
//! construction, non-destructive command rewrite, and the controlling-terminal probe.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use super::pkexec::PkexecVersion;
use super::plan::{launches_pkexec, BackendSet, Host, Os, Transition};
use super::{Auth, Backend, ElevatedStdio, ElevatedVia, ElevationReport, Launch, Privilege, Secret};
use crate::command::{Command, EnvOp};
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
/// `pkexec` and `run0` are told to run the program in the directory they are started in, as `sudo`
/// and `doas` do unasked. Pure — no installed backend required.
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
            // polkit 121 and later; the rewrite refuses an older pkexec ([`super::pkexec`]).
            argv.push("--keep-cwd".into());
            debug_assert!(
                !program_starts_with_dash(program),
                "pkexec has no `--`; the structural gate refuses a leading-dash program"
            );
        }
        Backend::Run0 => {
            argv.push("--pipe".into());
            // `-D .`: run0 completes `.` against its own cwd.
            argv.push("-D".into());
            argv.push(".".into());
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
    // refused by the structural gate instead).
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

/// Path resolution over an explicit PATH value: check the exec bit and SKIP every
/// non-absolute element. An empty element means the cwd, and any relative one (`bin`, `.`)
/// names a directory under it: a backend found there would be exec-checked against the cwd at
/// detection and launched against whatever the cwd is later, so it is never resolved.
pub(super) fn resolve_in_path_var(path_var: &OsStr, program: &str) -> Option<PathBuf> {
    std::env::split_paths(path_var).find_map(|dir| {
        if !dir.is_absolute() {
            return None;
        }
        let cand = dir.join(program);
        is_executable(&cand).then_some(cand)
    })
}

/// Reads `sysctl kern.argmax` for [`Host::arg_max`]; `None` if the query fails.
#[cfg(target_os = "macos")]
fn kern_argmax() -> Option<usize> {
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: a two-element MIB with a matching `c_int` out-buffer and its exact
    // size; a read-only sysctl (null new-value, zero new-length).
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || value <= 0 {
        log::debug!("could not read kern.argmax; the elevation length guard is disabled");
        return None;
    }
    Some(value as usize)
}

/// [`Host::pkexec_version`]: `run` `pkexec --version` on the `pinned` file, with `path` (its
/// canonical path) as `argv[0]`.
pub(crate) fn probe_pkexec(
    path: &Path,
    pinned: &File,
    run: impl FnOnce(std::process::Command) -> PkexecVersion,
) -> PkexecVersion {
    use std::os::unix::process::CommandExt;
    let mut probe = std::process::Command::new(pinned_exec_path(pinned));
    probe.arg0(path).arg("--version");
    run(probe)
}

/// `/proc/self/fd/N` for `pinned`: exec'd, it runs the pinned file itself, setuid honoured
/// (measured, polkit 121–127). Resolved before the close-on-exec descriptor closes, so it serves an
/// ELF; a script's interpreter would find it gone. Linux only, as pkexec's `/proc` use is.
fn pinned_exec_path(pinned: &File) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
}

/// Open `real` for [`Host::pkexec_pin`]: `O_PATH` on Linux (exec needs no read permission),
/// read-only elsewhere, close-on-exec, non-blocking (a FIFO renamed in cannot stall the open), not
/// through a symlink, and only a regular file. Moved to 3 or above when it
/// lands lower, so no child's stdio setup can replace it before the exec.
fn pin(real: &Path) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "linux")]
    let path_only = libc::O_PATH;
    #[cfg(not(target_os = "linux"))]
    let path_only = 0;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(path_only | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(real)?;
    // Linux's `O_PATH | O_NOFOLLOW` opens a symlink as itself rather than failing.
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if file.as_raw_fd() >= 3 {
        return Ok(file);
    }
    // SAFETY: duplicating a descriptor this function owns; the result is checked.
    let moved = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if moved < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `moved` is a fresh descriptor owned by nothing else.
    Ok(unsafe { File::from_raw_fd(moved) })
}

/// Run `probe` with an empty environment and read its stdout as [`super::pkexec::parse`] does.
pub(crate) fn run_version_probe(mut probe: std::process::Command) -> PkexecVersion {
    probe
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let spawned = {
        // Every fork in this process holds it; see `crate::child::spawn::spawn_lock`.
        let _guard = crate::child::spawn::spawn_lock();
        probe.spawn()
    };
    match spawned.and_then(std::process::Child::wait_with_output) {
        Err(e) => PkexecVersion::SpawnFailed(e.to_string()),
        Ok(out) if !out.status.success() => PkexecVersion::Failed {
            status: out.status.to_string(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        },
        Ok(out) => super::pkexec::parse(&out.stdout),
    }
}

/// `pkexec` on `path_var` ([`resolve_in_path_var`]), with every symlink followed to the real file
/// by `canonicalize`, which detection then pins ([`pin`]): the probe and the launch exec that
/// file. `None` if `PATH` has no pkexec; `Err` with the match if its real file cannot be found.
pub(crate) fn pkexec_on(
    path_var: &OsStr,
    canonicalize: impl FnOnce(&Path) -> std::io::Result<PathBuf>,
) -> Option<Result<PathBuf, (PathBuf, std::io::Error)>> {
    let found = resolve_in_path_var(path_var, "pkexec")?;
    Some(canonicalize(&found).map_err(|e| (found, e)))
}

/// The [`Os`] this build runs on.
fn host_os() -> Os {
    if cfg!(target_os = "macos") {
        Os::MacOs
    } else if cfg!(target_os = "linux") {
        Os::Linux
    } else {
        Os::Unix
    }
}

pub(super) fn detect(backend: Backend, auth: &Auth) -> Host {
    detect_with(
        std::env::var_os("PATH").as_deref(),
        host_os(),
        is_elevated(),
        backend,
        auth,
        |p| std::fs::canonicalize(p),
        run_version_probe,
    )
}

/// [`detect`] over an explicit `PATH`, OS and privilege, resolving pkexec's real file with
/// `canonicalize` and `run`ning the pkexec probe. The pkexec it stores is the one it probed.
pub(crate) fn detect_with(
    path_var: Option<&OsStr>,
    os: Os,
    elevated: bool,
    backend: Backend,
    auth: &Auth,
    canonicalize: impl FnOnce(&Path) -> std::io::Result<PathBuf>,
    run: impl FnOnce(std::process::Command) -> PkexecVersion,
) -> Host {
    let on_path = |program| path_var.and_then(|p| resolve_in_path_var(p, program));
    let unresolved = |found: &Path, error: String| PkexecVersion::Unresolved {
        path: found.display().to_string(),
        error,
    };
    let (pkexec, pkexec_pin, pkexec_version) = if !launches_pkexec(os, backend, auth, elevated) {
        (on_path("pkexec"), None, PkexecVersion::NotProbed)
    } else {
        match path_var.and_then(|p| pkexec_on(p, canonicalize)) {
            None => (None, None, PkexecVersion::NotProbed),
            Some(Err((found, e))) => (None, None, unresolved(&found, e.to_string())),
            Some(Ok(real)) => match pin(&real) {
                Ok(pinned) => {
                    let version = probe_pkexec(&real, &pinned, run);
                    (Some(real), Some(std::sync::Arc::new(pinned)), version)
                }
                Err(e) => {
                    let error = format!("opening {}: {e}", real.display());
                    (None, None, unresolved(&real, error))
                }
            },
        }
    };
    Host {
        elevated,
        has_tty: controlling_terminal_present(),
        available: BackendSet {
            run0: on_path("run0"),
            sudo: on_path("sudo"),
            doas: on_path("doas"),
            pkexec,
            // A fixed system path, never PATH-resolved: a PATH lookup would let a
            // shadowing `osascript` earlier on PATH receive an elevation request.
            osascript: {
                #[cfg(target_os = "macos")]
                {
                    let p = Path::new("/usr/bin/osascript");
                    is_executable(p).then(|| p.to_path_buf())
                }
                #[cfg(not(target_os = "macos"))]
                {
                    None
                }
            },
        },
        os,
        arg_max: {
            #[cfg(target_os = "macos")]
            {
                kern_argmax()
            }
            #[cfg(not(target_os = "macos"))]
            {
                None
            }
        },
        pkexec_version,
        pkexec_pin,
    }
}

// ===== Non-destructive rewrite + deferred password channel =====
//
// The deferred-password chain (`PendingPassword`/`password_line`/`write_*`) and the
// `PosixRewrite` fields are consumed by the sync and async POSIX spawn arms.

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

/// The argv, refused unless a backend can wrap it ([`super::elevation_argv`]).
fn checked_argv(cmd: &Command) -> Result<&[OsString], Error> {
    super::elevation_argv(
        cmd,
        &super::ArgvRefusals {
            platform: "unix",
            op_prefix: "elevation",
            commandline: "elevation requires an argv command (set .args([...])); a raw command line cannot be \
                          safely wrapped",
            argv0: "the backend runs the loaded file with argv[0] = its path; a separate argv[0] cannot \
                    survive elevation",
        },
    )
}

/// Program + args + directory for a POSIX backend: a `raw_executable()` program in the unelevated
/// spawn's form ([`crate::resolve::exact::anchor_posix`] — `./tool`), and `current_dir()` as
/// given, entered by the wrapper at `fork`. Reads nothing. Every backend runs the program in the
/// directory it is started in: `sudo` and `doas` unasked, `pkexec` told `--keep-cwd` and `run0`
/// `-D .` ([`build_argv`]).
///
/// `sudo` and `doas` read `./tool` against the directory object they inherited, after
/// authenticating, so a rename of an ancestor during the prompt cannot swap the file loaded; an
/// absolute path would be re-resolved then. Measured under `sudo -S`, blocked on its password
/// while an ancestor was renamed and another tree moved into its place: the absolute path ran the
/// substitute, `./tool` the original. `pkexec` and `run0` complete `./tool` against their cwd's
/// path themselves, before authenticating, so under them that rename can still redirect it.
///
/// A sudoers `runcwd` moves `sudo`'s child before the exec, and `./tool` is then read there —
/// measured: `sudo: unable to execute ./tool: No such file or directory` under `runcwd=~`. That
/// directory is the administrator's choice, as `secure_path` is for a bare name, so this never
/// loads a file an unprivileged user placed; the absolute path, which would load the named file
/// there, is the one a rename can swap.
fn anchored_program_and_args(cmd: &Command) -> Result<Launch, Error> {
    let argv = checked_argv(cmd)?;
    let program = match cmd.executable_spec() {
        Some(crate::command::ExecutableSpec::Exact(p)) => {
            crate::resolve::exact::anchor_posix(p.as_os_str(), cmd.cwd())?
                .program
                .into_os_string()
        }
        Some(crate::command::ExecutableSpec::Search(p)) => p.as_os_str().to_os_string(),
        None => argv[0].clone(),
    };
    Ok(Launch {
        program,
        args: argv[1..].to_vec(),
        cwd: cmd.cwd().map(Path::to_path_buf),
    })
}

/// Structural request-validation, evaluated against the REQUESTED backend so the verdict
/// is privilege-independent. Run BEFORE the already-elevated short-circuit, so an
/// already-elevated caller gets the same rejection. (Backend availability + NoTty are
/// environmental and stay in the planner, after the short-circuit.)
///
/// Reads nothing: an already-root caller runs no backend, and needs no path to its cwd.
fn reject_structural_posix_config(cmd: &Command, backend: Backend, auth: &Auth) -> Result<(), Error> {
    // commandline() / empty / distinct-argv0, and a `raw_executable()` that names no file.
    checked_argv(cmd)?;
    if let Some(crate::command::ExecutableSpec::Exact(p)) = cmd.executable_spec() {
        crate::resolve::exact::refuse_unnameable(p.as_os_str())?;
        use std::os::unix::ffi::OsStrExt;
        // pkexec runs a relative program only if the caller itself can execute it (GLib's
        // `g_find_program_in_path`: `access(X_OK)` with the real uid), so a root-only one fails.
        if backend == Backend::Pkexec && p.as_os_str().as_bytes().first() != Some(&b'/') {
            return Err(Error::Unsupported {
                op: "a relative raw_executable() under pkexec".into(),
                platform: "unix",
                detail: format!("pkexec requires an absolute program path; pass one instead of {p:?}"),
            });
        }
    }
    // pkexec has no `--` terminator, so a program starting with `-` would be taken for an option.
    if backend == Backend::Pkexec {
        let program = match cmd.executable_spec() {
            Some(spec) => spec.path().as_os_str(),
            None => checked_argv(cmd)?[0].as_os_str(),
        };
        if program_starts_with_dash(program) {
            return Err(Error::Unsupported {
                op: "elevating a leading-dash program under pkexec".into(),
                platform: "unix",
                detail: "pkexec cannot parse a `--` terminator, so a program starting with `-` would be taken \
                         as a pkexec option; use sudo/doas/run0, or a path such as ./-x"
                    .into(),
            });
        }
    }
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

/// Transfer the caller's cwd (the [`Launch`]'s, so it matches the program) /
/// containment / kill-on-drop onto the derived command.
/// Does NOT suppress the fd marker — that is only correct for a real wrapper spawn
/// (`ElevatePosix`), whose `closefrom` destroys it; `RunAsIs`'s derived command spawns the
/// original program directly, with no wrapper to destroy anything, so its caller must
/// suppress explicitly if that arm ever needs to.
fn transfer_process_attrs(derived: &mut Command, cmd: &Command, cwd: Option<PathBuf>) {
    if let Some(d) = cwd {
        derived.current_dir(d);
    }
    derived.set_contain(cmd.contain_request());
    derived.kill_on_drop(cmd.kill_on_drop_flag());
}

/// Detect-then-plan-then-rewrite. Thin wrapper over the pure form.
// Consumed by the sync POSIX spawn arm (`crate::child::spawn::spawn`); the pure
// `rewrite_with_host` is what the tests drive directly.
pub(crate) fn rewrite(cmd: &mut Command) -> Result<PosixRewrite, Error> {
    // Before detection, so a request refused for its shape never runs pkexec's version probe.
    reject_structural(cmd, host_os())?;
    let request = cmd.elevation_request();
    let host = Host::detect(request.backend, &request.auth);
    rewrite_with_host(cmd, &host)
}

/// Structural config gates — privilege-independent, so run before the already-elevated
/// short-circuit. Which gate applies is a property of the REQUEST, not the run — see
/// `is_macos_gui_auto`'s doc and the ambient-privilege invariant `structural_posix` documents.
/// Keying on the resolved `Transition` instead would break it: `plan()` yields `RunAsIs` under
/// root, so the same request would be accepted as root and rejected as a normal user.
fn reject_structural(cmd: &Command, os: Os) -> Result<(), Error> {
    let request = cmd.elevation_request();
    if super::plan::is_macos_gui_auto(os, request.backend, &request.auth) {
        super::macos::reject_structural_gui_config(cmd)
    } else {
        reject_structural_posix_config(cmd, request.backend, &request.auth)
    }
}

/// PURE given `host` (and, for a relative `raw_executable()` under osascript, this process's cwd):
/// gate + plan + sanitize + build a DERIVED command. The caller's `Command` `input`/`env_ops` are
/// left untouched (non-destructive): the caller's fd 0-2 stdio is MOVED into the derived command
/// (`ResolvedStdio::File` is not `Clone`).
pub(crate) fn rewrite_with_host(cmd: &mut Command, host: &Host) -> Result<PosixRewrite, Error> {
    rewrite_with_host_and_cwd(cmd, host, std::env::current_dir)
}

/// [`rewrite_with_host`], reading this process's cwd through `process_cwd` — at most once, so
/// the program and the directory it runs in cannot come from two different readings, and only
/// for osascript, whose trampoline carries no cwd and so needs a path.
pub(crate) fn rewrite_with_host_and_cwd(
    cmd: &mut Command,
    host: &Host,
    process_cwd: impl FnOnce() -> std::io::Result<PathBuf>,
) -> Result<PosixRewrite, Error> {
    let requested_backend = cmd.elevation_request().backend;
    let requested_auth = cmd.elevation_request().auth.clone();
    reject_structural(cmd, host.os)?;

    match host.plan(Privilege::Elevated, requested_backend, requested_auth) {
        Transition::Reject { error } => Err(error),
        Transition::ElevateWindows { .. } => unreachable!("planner never yields ElevateWindows on a unix host"),
        Transition::ElevateMacosGui { osascript, arg_max } => {
            let launch = super::macos::program_and_args(cmd, process_cwd)?;
            let (derived, report) = super::macos::build_rewrite(cmd, launch, &osascript, arg_max)?;
            Ok(PosixRewrite {
                derived: Some(derived),
                report: Some(report),
                password_write: None,
                // The derived program IS osascript, so an exec failure remaps to
                // BackendUnavailable exactly as it does for the POSIX backends.
                backend_path: Some(osascript),
            })
        }
        Transition::RunAsIs => {
            // Already elevated: no wrapper, but the sanitizer STILL runs so a dangerous
            // forwarded var never reaches the root child. Build a non-destructive derived
            // command (the ORIGINAL program, executable and args, sanitized env, fds MOVED).
            // No backend runs, so the derived command spawns as an unelevated one does, and a
            // `raw_executable()` needs no path to this process's cwd.
            let (kept, stripped) = cmd.elevation_request().sanitizer.apply(explicit_set_env(cmd.env_ops()));
            let env_ops: Vec<EnvOp> = kept.iter().map(|(k, v)| EnvOp::Set(k.clone(), v.clone())).collect();
            let mut derived = Command::new();
            derived.set_input_argv(checked_argv(cmd)?.to_vec());
            derived.set_executable_spec(cmd.executable_spec().cloned());
            derived.set_env_ops(env_ops);
            transfer_process_attrs(&mut derived, cmd, cmd.cwd().map(Path::to_path_buf));
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
            if backend == Backend::Pkexec {
                debug_assert!(
                    host.pkexec_version != PkexecVersion::NotProbed,
                    "detect asks a pkexec request's pkexec its version"
                );
                if let Some(refusal) = host.pkexec_version.refusal() {
                    return Err(refusal);
                }
            }
            // The launch execs the file detection pinned and probed, not whatever the path names now.
            let pinned = match (backend, &host.pkexec_pin) {
                (Backend::Pkexec, Some(pin)) => Some(pin.clone()),
                (Backend::Pkexec, None) => {
                    debug_assert!(false, "detect pins every pkexec it stores");
                    return Err(Error::Elevation {
                        kind: ElevationErrorKind::BackendUnavailable,
                        detail: "pkexec was not opened at detection".into(),
                    });
                }
                _ => None,
            };
            let Launch { program, args, cwd } = anchored_program_and_args(cmd)?;
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
            // An exec failure is judged on the file exec'd: the pinned one, while `derived` holds it.
            let mut backend_path = path;
            if let Some(pin) = pinned {
                // argv[0] stays the canonical path; `hold` keeps the descriptor open until the spawn.
                backend_path = pinned_exec_path(&pin);
                derived.set_executable_spec(Some(crate::command::ExecutableSpec::Exact(backend_path.clone())));
                derived.hold(pin);
            }
            derived.set_env_ops(new_ops);
            transfer_process_attrs(&mut derived, cmd, cwd);
            // Only THIS arm's derived command is a real wrapper spawn (`sudo`/`doas`/`pkexec`
            // …): its `closefrom` destroys an installed marker, so the marker must not be
            // installed on it at all. `RunAsIs` spawns the original program with no wrapper —
            // suppressing there would claim a false justification (see `transfer_process_attrs`).
            derived.suppress_fd_marker();

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
                backend_path: Some(backend_path),
            })
        }
    }
}

#[cfg(test)]
#[path = "posix_tests.rs"]
mod posix_tests;
