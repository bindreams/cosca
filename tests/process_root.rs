//! `foreign_kill_surfaces_permission_denied`: a genuinely foreign, unprivileged caller's `kill`
//! on a genuinely foreign, unprivileged target must surface `EPERM` as `Err`, never swallow it
//! into `Ok`. Split out of `tests/process.rs` (which keeps the ordinary, non-root foreign-process
//! tests): the uid-switching/re-exec machinery and the `ROOT` label/precondition CI keys its root
//! step on are a separate concern, and living in their own binary lets a future root test reuse
//! `tests/common/`'s pieces without dragging this one in. Unix-only, like the test itself.

#[path = "common/mod.rs"]
mod common;
#[cfg(unix)]
use common::consent_root;

/// Set on this binary's own re-exec of itself, routing `fn main` (bottom of this file) to
/// [`foreign_kill_helper_main`] instead of the skuld harness — checked before skuld ever parses
/// argv, so the re-exec'd process never itself becomes a skuld test run.
#[cfg(unix)]
const ENV_TARGET_PID: &str = "COSCA_FOREIGN_KILL_TARGET_PID";

/// See the module doc. Runs only once its `ROOT` group's switch AND consent both hold
/// (`common::preconditions::root`, `#[fixture(consent_root)]`, label `ROOT`) — this test changes
/// real system state (two uid switches), so it needs explicit consent, not just the switch being
/// on. `common::assert_root_capable()` then asserts the ACTUAL requirement (root, and on Linux
/// the ability to setuid/setgid to both `TARGET_UID` and `READER_UID`): a missing capability at
/// that point FAILS the test — switch-on-plus-consent is a promise the environment can do this,
/// and a broken promise is a failure, not "unavailable".
///
/// Both the target and the actual caller under test run as ordinary child PROCESSES of this
/// (root) one — never as this process itself — so root can always name and clean up the target
/// regardless of what the assertions below do.
///
/// The target crosses to the reader as a bare pid: this process holds its unreaped
/// `std::process::Child`, so the kernel cannot recycle the pid before the reader reports back.
#[cfg(unix)]
#[skuld::test(requires = [common::preconditions::root], labels = [common::ROOT])]
fn foreign_kill_surfaces_permission_denied(#[fixture(consent_root)] _consent: &()) {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

    use common::KillOnDrop;

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
    let target = {
        let _guard = cosca::test_spawn_lock();
        std::process::Command::new(&target_bin)
            .args(["control-echo-pid", &addr, "R"])
            .uid(common::TARGET_UID)
            .gid(common::TARGET_UID)
            .spawn()
            .expect("spawn the target under an unprivileged uid")
    };
    let target = KillOnDrop::new(target);
    let target_pid = target.id();

    let mut sock = common::accept_or_die(&listener, target_pid);
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

    // Restores the "must not kill" half of the contract: a kill that both delivers the signal
    // AND returns Err(EPERM) would otherwise still pass the assertion above. A bare
    // `try_wait() == None` would be a timing race (a SIGKILL can be in flight, not yet reaped) —
    // a ping/pong round trip on the target's own control socket instead PROVES it is still alive
    // AND responsive, not merely "not yet observed dead".
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
