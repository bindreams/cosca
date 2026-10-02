//! Regression fixture for the root `clippy.toml`'s `disallowed-methods` bans. Not part of the
//! cosca package (see `.github/scripts/check-disallowed-methods.sh`, which runs clippy here
//! against the real `clippy.toml` via `CLIPPY_CONF_DIR` and asserts a
//! `clippy::disallowed_methods` diagnostic for each call below). If any of these stops failing
//! clippy, the ban has gone silently dead — a renamed `disallowed-methods` key, a typo'd path, or
//! a dependency upgrade that moved the function.

#![allow(dead_code, reason = "exists only to be flagged by clippy::disallowed_methods")]

use std::time::Duration;

// Pipes =====

#[cfg(unix)]
fn calls_libc_pipe() {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
}

#[cfg(unix)]
fn calls_nix_pipe() {
    let _ = nix::unistd::pipe();
}

#[cfg(target_os = "linux")]
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

async fn calls_tokio_timeout() {
    let _ = tokio::time::timeout(Duration::ZERO, async {}).await;
}

async fn calls_tokio_timeout_at() {
    let _ = tokio::time::timeout_at(tokio::time::Instant::now(), async {}).await;
}

async fn calls_tokio_sleep() {
    tokio::time::sleep(Duration::ZERO).await;
}

async fn calls_tokio_sleep_until() {
    tokio::time::sleep_until(tokio::time::Instant::now()).await;
}

fn calls_tokio_interval() {
    let _ = tokio::time::interval(Duration::from_secs(1));
}

fn calls_tokio_interval_at() {
    let _ = tokio::time::interval_at(tokio::time::Instant::now(), Duration::from_secs(1));
}

// The re-arm methods take their receiver as a parameter, so no other banned constructor is needed
// to reach them and each diagnostic stands alone.

fn calls_tokio_sleep_reset(sleep: std::pin::Pin<&mut tokio::time::Sleep>) {
    sleep.reset(tokio::time::Instant::now());
}

fn calls_tokio_interval_reset(interval: &mut tokio::time::Interval) {
    interval.reset();
}

fn calls_tokio_interval_reset_immediately(interval: &mut tokio::time::Interval) {
    interval.reset_immediately();
}

fn calls_tokio_interval_reset_after(interval: &mut tokio::time::Interval) {
    interval.reset_after(Duration::ZERO);
}

fn calls_tokio_interval_reset_at(interval: &mut tokio::time::Interval) {
    interval.reset_at(tokio::time::Instant::now());
}

// Process-cwd mutators =====
//
// `daemon(3)` chdirs to `/` unless `nochdir` is set. The `windows` and `windows_sys`
// `SetCurrentDirectory*` bans and the CRT `libc::chdir` are only reachable when the fixture is
// linted for a Windows target.

fn calls_std_set_current_dir() {
    let _ = std::env::set_current_dir("/");
}

#[cfg(any(unix, windows))]
fn calls_libc_chdir() {
    unsafe { libc::chdir(c"/".as_ptr()) };
}

// Apple dropped `daemon` from libc 0.2.190, so its ban is checked off macOS only.
#[cfg(all(unix, not(target_vendor = "apple")))]
fn calls_libc_daemon() {
    unsafe { libc::daemon(0, 0) };
}

#[cfg(target_os = "linux")]
fn calls_nix_daemon() {
    let _ = nix::unistd::daemon(false, false);
}

#[cfg(unix)]
fn calls_libc_fchdir() {
    unsafe { libc::fchdir(0) };
}

#[cfg(unix)]
fn calls_nix_chdir() {
    let _ = nix::unistd::chdir("/");
}

#[cfg(unix)]
fn calls_nix_fchdir() {
    let _ = nix::unistd::fchdir(std::io::stdin());
}

#[cfg(target_os = "linux")]
fn calls_rustix_chdir() {
    let _ = rustix::process::chdir("/");
}

#[cfg(target_os = "linux")]
fn calls_rustix_fchdir() {
    let _ = rustix::process::fchdir(std::io::stdin());
}

#[cfg(target_os = "linux")]
fn calls_rustix_dir_chdir(dir: &rustix::fs::Dir) {
    let _ = dir.chdir();
}

#[cfg(windows)]
fn calls_windows_set_current_directory_a() {
    let _ = unsafe { windows::Win32::System::Environment::SetCurrentDirectoryA(windows::core::s!("C:\\")) };
}

#[cfg(windows)]
fn calls_windows_set_current_directory_w() {
    let _ = unsafe { windows::Win32::System::Environment::SetCurrentDirectoryW(windows::core::w!("C:\\")) };
}

#[cfg(windows)]
fn calls_windows_sys_set_current_directory_a() {
    unsafe { windows_sys::Win32::System::Environment::SetCurrentDirectoryA(c"C:\\".as_ptr().cast()) };
}

#[cfg(windows)]
fn calls_windows_sys_set_current_directory_w() {
    unsafe { windows_sys::Win32::System::Environment::SetCurrentDirectoryW([0u16].as_ptr()) };
}
