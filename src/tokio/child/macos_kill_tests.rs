//! macOS: a tokio child's signals go by pid only while the pid still has the unique id read at
//! spawn.

use crate::send_log::{Capture, Via};
use crate::tokio::Command;

/// A blocker that exited and was reaped by a foreign `waitpid`, behind tokio's back.
async fn foreign_reaped_blocker() -> crate::tokio::Child {
    let (stdin, writer) = crate::test_child::held_writer_stdin();
    let mut cmd = Command::new();
    cmd.args(crate::test_child::BLOCKER_ARGV.iter().copied());
    cmd.stdin(stdin).expect("set stdin");
    let child = cmd.spawn().expect("spawn");
    let pid = child.id().pid();
    drop(writer);

    // SAFETY: an all-zero `siginfo_t` is valid, and `waitid` writes only into it.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waits for our own child's exit without consuming it.
    let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, libc::WEXITED | libc::WNOWAIT) };
    assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    let mut status = 0;
    // SAFETY: reaps our own exited child behind tokio's back.
    let reaped = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    assert_eq!(
        reaped,
        pid as libc::pid_t,
        "waitpid: {}",
        std::io::Error::last_os_error()
    );
    child
}

/// A child reaped by a foreign `waitpid` has no unique id any more, so `kill` answers `Ok` and
/// sends nothing by pid. The log records an attempt before its syscall, so a mutant's `kill(2)`
/// still shows even though it fails with `ESRCH`.
///
/// Mutants: `kill` via tokio's `start_kill` (answers `Err(ESRCH)`); no identity check before the
/// by-pid send (the log shows `Via::Pid`).
#[tokio::test(flavor = "current_thread")]
async fn macos_tokio_kill_after_a_foreign_reap_sends_nothing() {
    let mut child = foreign_reaped_blocker().await;
    let log = Capture::start();
    child.kill().expect("a kill of a foreign-reaped child answers Ok");
    let sent_by_pid: Vec<_> = log
        .entries()
        .into_iter()
        .filter(|(_, _, via)| *via == Via::Pid)
        .collect();
    assert!(sent_by_pid.is_empty(), "nothing may be sent by pid: {sent_by_pid:?}");
}

// What shows a child was reaped by someone else =====

/// A raw tokio child that exited and is not reaped, behind a backend that holds `identity(real)`.
fn exited_unreaped_with(identity: impl FnOnce(u64) -> Option<u64>) -> (super::proc_source::ProcSource, u32) {
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::from(crate::test_reexec::command(
            std::env::current_exe().expect("current_exe"),
        ))
        .args(["--exact", "__cosca_no_such_test__"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    crate::test_child::wait_until_zombie(pid);
    let real = crate::signal::read_identity(pid)
        .expect("readable")
        .expect("a zombie still has a unique id");
    (super::proc_source::ProcSource::new(child, identity(real)), pid)
}

/// Mutant: `reaped_elsewhere` answers `true` for the child's own unreaped zombie.
#[tokio::test(flavor = "current_thread")]
async fn macos_a_child_with_its_own_unique_id_is_not_reaped_elsewhere() {
    let (proc, _pid) = exited_unreaped_with(Some);
    assert!(!proc.reaped_elsewhere());
}

/// Mutant: the unique id is not compared.
#[tokio::test(flavor = "current_thread")]
async fn macos_a_pid_with_another_unique_id_is_reaped_elsewhere() {
    let (proc, _pid) = exited_unreaped_with(|real| Some(real ^ 1));
    assert!(proc.reaped_elsewhere());
}

/// Mutant: a child with no unique id is taken for one that can be verified.
#[tokio::test(flavor = "current_thread")]
async fn macos_a_child_with_no_unique_id_is_reaped_elsewhere() {
    let (proc, _pid) = exited_unreaped_with(|_| None);
    assert!(proc.reaped_elsewhere());
}

/// A failed peek cannot show the child is ours: it counts as reaped elsewhere, and the warning
/// carries the error.
///
/// Mutant: a failed peek is no evidence.
#[tokio::test(flavor = "current_thread")]
async fn macos_a_failed_peek_is_reaped_elsewhere_and_warns_with_the_error() {
    use crate::wait::exit_only::seams::force_peek_once;
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let (proc, _pid) = exited_unreaped_with(Some);
    let _failed = force_peek_once(Err(std::io::Error::other("forced peek failure 7c3e")));

    assert!(proc.reaped_elsewhere());
    assert!(crate::log_capture::contains_since(mark, "forced peek failure 7c3e"));
}

/// A child still running whose unique id cannot be read (a MACF denial) cannot be shown to be ours:
/// the peek answers `Running`, but the id is the only thing that tells it from a reuse of the pid,
/// so the backend counts it as reaped elsewhere and the child is forgotten, never released to
/// tokio's by-pid reap.
///
/// Mutant: `reaped_elsewhere` takes a `Running` peek with an unreadable id as "ours".
#[tokio::test(flavor = "current_thread")]
async fn macos_a_running_child_whose_unique_id_read_is_refused_is_reaped_elsewhere() {
    use crate::identity::{uniq_fault, ReadPurpose, UniqRead};
    crate::log_capture::install();
    let mark = crate::log_capture::mark();
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("sleep")
            .arg("600")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let real = crate::signal::read_identity(pid)
        .expect("readable")
        .expect("a running child has a unique id");
    let proc = super::proc_source::ProcSource::new(child, Some(real));
    let _refused = uniq_fault::force_uniq_read_once(ReadPurpose::Running, UniqRead::Refused(libc::EPERM));

    let reaped_elsewhere = proc.reaped_elsewhere();

    // The child is ours and unreaped: end it before asserting.
    proc.signal(crate::signal::Sig::Kill).expect("kill our own child");
    proc.release(); // tokio's orphan queue reaps the killed child
    assert!(reaped_elsewhere, "an id that cannot be read does not show the pid is ours");
    assert!(crate::log_capture::contains_since(mark, "cannot be shown to be ours"));
}

/// Dropping a backend that nothing released or forgot (an unwind does this) leaves the child to
/// the OS rather than to tokio's by-pid reap, since macOS has no handle to verify it by.
///
/// Mutant: the implicit drop releases tokio's `Child`.
#[tokio::test(flavor = "current_thread")]
async fn macos_dropping_a_backend_implicitly_forgets_it_and_leaves_the_child_running() {
    let child = crate::test_spawn::spawn_tokio(
        ::tokio::process::Command::new("sleep")
            .arg("600")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null()),
    )
    .expect("spawn");
    let pid = child.id().expect("tokio owns an un-reaped child");
    let identity = crate::signal::read_identity(pid).expect("readable");
    let proc = super::proc_source::ProcSource::new(child, identity);
    let backend_drops = super::fault::count_backend_drops();

    drop(proc);

    assert_eq!(backend_drops.get(), 0, "tokio's Child must have been forgotten");
    // SAFETY: `pid` is this test's own child, which nothing has reaped (its backend was forgotten).
    unsafe {
        assert_eq!(libc::kill(pid as libc::pid_t, libc::SIGKILL), 0, "the child is still ours");
        let mut status = 0;
        assert_eq!(libc::waitpid(pid as libc::pid_t, &mut status, 0), pid as libc::pid_t);
    }
}

/// A drop whose child was reaped by someone else forgets tokio's `Child`: the backend is not
/// dropped, so tokio's by-pid reap never runs.
///
/// Mutant: the drop does not forget.
#[tokio::test(flavor = "current_thread")]
async fn macos_drop_after_a_foreign_reap_forgets_tokios_child() {
    let child = foreign_reaped_blocker().await;
    let root = super::drop_fault::record();
    let backend_drops = super::fault::count_backend_drops();

    drop(child);

    assert_eq!(root.forgets(), 1);
    assert_eq!(backend_drops.get(), 0, "tokio's Child must not have been dropped");
}

/// `finish_elevated` after a foreign reap says the child could not be terminated, and waits for
/// nothing by pid.
///
/// Mutant: `kill`'s `Ok` for a gone child is read as "terminated".
#[tokio::test(flavor = "current_thread")]
async fn macos_finish_elevated_after_a_foreign_reap_does_not_claim_a_termination() {
    let child = foreign_reaped_blocker().await;

    let err = crate::tokio::spawn::finish_elevated(
        child,
        Err(crate::error::Error::Elevation {
            kind: crate::error::ElevationErrorKind::AuthFailed,
            detail: "forced password-write failure".into(),
        }),
    )
    .expect_err("the spawn fails");

    let crate::error::Error::Elevation { detail, .. } = err else {
        panic!("expected an Elevation error, got {err:?}");
    };
    assert!(detail.contains("could not be terminated"), "{detail}");
    assert!(!detail.contains("was terminated"), "{detail}");
}
