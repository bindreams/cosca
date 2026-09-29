//! Regression fixture for the root `clippy.toml`'s `disallowed-methods` bans. Not part of the
//! cosca package (see `.github/scripts/check-disallowed-methods.sh`, which runs clippy here
//! against the real `clippy.toml` via `CLIPPY_CONF_DIR` and asserts a
//! `clippy::disallowed_methods` diagnostic for each call below). If any of these stops failing
//! clippy, the ban has gone silently dead — a renamed `disallowed-methods` key, a typo'd path, or
//! a dependency upgrade that moved the function.

use std::time::Duration;

// Pipes =====

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

// Raw process spawns =====

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_std_command_spawn_output_status() {
    let _ = std::process::Command::new("x").spawn();
    let _ = std::process::Command::new("x").output();
    let _ = std::process::Command::new("x").status();
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
async fn calls_tokio_command_spawn_output_status() {
    let _ = tokio::process::Command::new("x").spawn();
    let _ = tokio::process::Command::new("x").output().await;
    let _ = tokio::process::Command::new("x").status().await;
}

// Tokio timers =====

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
async fn calls_tokio_timeout() {
    let _ = tokio::time::timeout(Duration::ZERO, async {}).await;
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
async fn calls_tokio_timeout_at() {
    let _ = tokio::time::timeout_at(tokio::time::Instant::now(), async {}).await;
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
async fn calls_tokio_sleep() {
    tokio::time::sleep(Duration::ZERO).await;
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
async fn calls_tokio_sleep_until() {
    tokio::time::sleep_until(tokio::time::Instant::now()).await;
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval() {
    let _ = tokio::time::interval(Duration::from_secs(1));
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval_at() {
    let _ = tokio::time::interval_at(tokio::time::Instant::now(), Duration::from_secs(1));
}

// The re-arm methods take their receiver as a parameter, so no other banned constructor is needed
// to reach them and each diagnostic stands alone.

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_sleep_reset(sleep: std::pin::Pin<&mut tokio::time::Sleep>) {
    sleep.reset(tokio::time::Instant::now());
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval_reset(interval: &mut tokio::time::Interval) {
    interval.reset();
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval_reset_immediately(interval: &mut tokio::time::Interval) {
    interval.reset_immediately();
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval_reset_after(interval: &mut tokio::time::Interval) {
    interval.reset_after(Duration::ZERO);
}

#[allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]
fn calls_tokio_interval_reset_at(interval: &mut tokio::time::Interval) {
    interval.reset_at(tokio::time::Instant::now());
}
