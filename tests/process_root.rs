//! `foreign_kill_surfaces_permission_denied`: a foreign, unprivileged caller's `kill` on a foreign,
//! unprivileged target surfaces `EPERM` as `Err`, never `Ok`. It is the `UID_SWITCH` group
//! (`COSCA_TEST_UID_SWITCH`, principles 9 and 10): it runs as root and switches to real uids.

#[path = "common/mod.rs"]
mod common;

/// Set on this binary's own re-exec of itself, routing `fn main` (bottom of this file) to
/// [`foreign_kill_helper_main`] instead of the skuld harness — checked before skuld ever parses
/// argv, so the re-exec'd process never itself becomes a skuld test run.
#[cfg(unix)]
const ENV_TARGET_PID: &str = "COSCA_FOREIGN_KILL_TARGET_PID";

/// Runs only when `COSCA_TEST_UID_SWITCH` is not `0` and `COSCA_TEST_UID_SWITCH_CONSENT=1`;
/// `common::assert_root_capable` then fails the test if the process cannot actually switch uids.
///
/// The target and the caller under test both run as child processes of this (root) one, never as
/// this process, so root can always name and clean up the target. The target crosses to the reader
/// as a bare pid: this process holds its unreaped `Child`, so the kernel cannot recycle the pid
/// before the reader reports back.
#[cfg(unix)]
#[skuld::test]
fn foreign_kill_surfaces_permission_denied() {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use common::KillOnDrop;

    if !common::require_group("UID_SWITCH") {
        return;
    }
    common::assert_root_capable();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind control listener");
    let addr = listener.local_addr().unwrap().to_string();

    // execve as another uid needs o+x on every ancestor directory, and $HOME (Linux) or the
    // per-user $TMPDIR (macOS) commonly lacks it. Copy both binaries into a 0755 dir directly
    // under /tmp, which both platforms keep traversable.
    let scratch = tempfile::Builder::new()
        .tempdir_in("/tmp")
        .expect("scratch directory for world-executable copies");
    std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod the scratch directory world-traversable");
    let target_bin = common::world_executable_copy(std::path::Path::new(common::testbin()), scratch.path());

    // The target. `cosca::Command` has no uid()/gid() (a cross-platform builder — Windows has no
    // such concept), so this one spawn uses `std::process::Command` directly, under the spawn
    // lock like every raw fork in this suite (see `common::output_locked`). `control-echo-pid`,
    // not `control-block`: the survival check below needs a target that stays responsive, not
    // merely present, to prove the denied kill didn't land.
    let target = common::spawn_locked(
        std::process::Command::new(&target_bin)
            .args(["control-echo-pid", &addr, "R"])
            .env(common::ACK_ENV, "1") // `accept_or_die` acks; the target reads it before sending its tag
            .uid(common::TARGET_UID)
            .gid(common::TARGET_UID),
    )
    .expect("spawn the target under an unprivileged uid");
    let mut target = KillOnDrop::new(target);
    let target_pid = target.id();

    let mut sock = common::accept_or_die(&listener, &mut target);
    let (tag, reported_pid) = common::read_tag_and_pid(&mut sock);
    assert_eq!(tag, b'R', "unexpected control tag from the target");
    assert_eq!(
        reported_pid, target_pid,
        "the target's self-reported pid must match what we spawned"
    );

    // The actual caller under test: re-exec THIS SAME test binary (another world-executable
    // copy — see above) as READER_UID. Its result crosses back as an exit code ONLY (never
    // parsed text) — see `foreign_kill_helper_main`'s doc for the exact mapping.
    let exe = std::env::current_exe().expect("this test binary's own path");
    let reader_bin = common::world_executable_copy(&exe, scratch.path());
    let status = common::status_locked(
        std::process::Command::new(&reader_bin)
            .uid(common::READER_UID)
            .gid(common::READER_UID)
            .env(ENV_TARGET_PID, target_pid.to_string()),
    )
    .expect("re-exec this binary as the unprivileged reader");

    assert_eq!(
        status.code(),
        Some(0),
        "the unprivileged reader did not confirm EPERM (see its stderr, above, for which check \
         failed) — got exit code {:?}",
        status.code()
    );

    // The target was alive and answering while the reader was refused, so the EPERM came from a
    // live foreign process. A bare `try_wait() == None` would only show it not yet reaped.
    common::assert_echoes(&mut sock, "the target");
}

/// [`foreign_kill_surfaces_permission_denied`]'s re-exec'd helper mode — dispatched from `fn
/// main` (bottom of this file) via `ENV_TARGET_PID`, before skuld ever sees argv. Reports its
/// verdict PURELY via the process exit code:
/// - `0`: `Process::kill` on the target surfaced `EPERM` as `Err` — the expected outcome.
/// - `10`: `kill` unexpectedly returned `Ok(())`.
/// - `11`: `kill` returned an `Err` other than `Io(EPERM)`.
/// - `12`: the target pid is `Gone` (no such process — a test bug, not an OS refusal).
/// - `13`: the target pid's identity is `Unknown` (the OS refused the query).
#[cfg(unix)]
fn foreign_kill_helper_main() -> i32 {
    // The caller's `Command::uid()/gid()` already runs setuid/setgid in its pre-exec child; a
    // failed drop would have made THAT spawn() return Err, which the caller `.expect()`s. So by
    // the time this process exists at all, the drop must have already succeeded.
    // SAFETY: geteuid() takes no arguments and has no preconditions.
    debug_assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "reached foreign_kill_helper_main still euid 0 — the caller's own Command::uid()/gid() \
         should have failed spawn() first if the drop to READER_UID failed"
    );
    let pid_str = std::env::var(ENV_TARGET_PID).expect("ENV_TARGET_PID set by the caller");
    let pid: cosca::identity::RawPid = pid_str.parse().expect("ENV_TARGET_PID is a valid pid");
    let target = match cosca::Process::from_pid(pid) {
        cosca::identity::Resolved::Found(p) => p,
        cosca::identity::Resolved::Gone => {
            eprintln!("foreign_kill_helper: target pid {pid} is gone");
            return 12;
        }
        cosca::identity::Resolved::Unknown => {
            eprintln!("foreign_kill_helper: target pid {pid}'s identity query was refused by the OS");
            return 13;
        }
    };
    match target.kill() {
        Err(cosca::error::Error::Io(e)) if e.raw_os_error() == Some(libc::EPERM) => 0,
        Ok(()) => {
            eprintln!("foreign_kill_helper: kill() unexpectedly succeeded");
            10
        }
        other => {
            eprintln!("foreign_kill_helper: kill() returned an unexpected result: {other:?}");
            11
        }
    }
}

fn main() {
    // Helper re-exec must bypass skuld (see ENV_TARGET_PID).
    #[cfg(unix)]
    if std::env::var_os(ENV_TARGET_PID).is_some() {
        std::process::exit(foreign_kill_helper_main());
    }
    skuld::run_all();
}
