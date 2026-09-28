//! Regression fixture for the root `clippy.toml`'s pipe ban. Not part of the cosca package (see
//! `.github/scripts/check-disallowed-pipes.sh`, which runs clippy here against the real
//! `clippy.toml` via `CLIPPY_CONF_DIR` and asserts a `clippy::disallowed_methods` diagnostic for
//! each call below). If any of these stops failing clippy, the ban has gone silently dead — a
//! renamed `disallowed-methods` key, a typo'd path, or a dependency upgrade that moved the
//! function.

#[cfg(unix)]
#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_libc_pipe() {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
}

#[cfg(unix)]
#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_nix_pipe() {
    let _ = nix::unistd::pipe();
}

#[cfg(target_os = "linux")]
#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_rustix_pipe() {
    let _ = rustix::pipe::pipe();
}
