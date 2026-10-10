//! cosca's end of the channel going away, and writers that are not cosca.

use super::rig::Owner;
use super::*;
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::protocol::{Frame, Refusal};

/// A shim for `spec`, whose owner is `owner`.
pub(super) fn owned_by(rig: &ShimRig, owner: &Owner, spec: Spec) -> rig::Run {
    rig.spawn(spec.cosca_pid(owner.pid).dir(&owner.dir))
}

pub(super) fn assert_never_started(done: &rig::Finished, marker: &Path, code: i32) {
    assert_never_started_after_the_clone(done, marker, code);
    assert!(!done.logged("forked child"), "{:#?}", done.lines);
}

/// As [`assert_never_started`], for a shim that has created the program's process and held it.
fn assert_never_started_after_the_clone(done: &rig::Finished, marker: &Path, code: i32) {
    assert_eq!(done.code, Some(code), "{}\n{:#?}", done.stderr, done.lines);
    assert!(done.stderr.contains(&format!("(exit {code})")), "{}", done.stderr);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn owner_exit_before_answer_is_123() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    // The acceptor never answers, and a copy of the listener keeps the connection open: only the
    // owner watch can tell the shim that cosca is gone.
    let mut owner = Owner::start("hold-copy");
    let mut run = owned_by(&rig, &owner, marker_program(&marker));
    run.wait_for("hello sent");
    owner.kill();
    // The copy's close ends a wait that ignored the owner, so that such a shim fails by its exit code.
    owner.close_stdin();
    let done = run.finish();
    assert_never_started(&done, &marker, 123);
    assert!(done.logged("cosca exited before the start"), "{:#?}", done.lines);
}

#[skuld::test]
fn owner_exit_after_a_is_123() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut owner = Owner::start("plain");
    let mut run = owned_by(&rig, &owner, marker_program(&marker).gate(Gate::AfterAnswer));
    // The `A` is read; cosca exits before the shim acts on it.
    run.wait_for("gate: waiting at after-answer");
    owner.kill();
    run.release(Gate::AfterAnswer);
    let done = run.finish();
    assert!(done.logged("first byte: A"), "{:#?}", done.lines);
    assert_never_started(&done, &marker, 123);
}

#[skuld::test]
fn owner_exit_between_the_recheck_and_the_clone_never_starts_the_program() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut owner = Owner::start("plain");
    let mut run = owned_by(
        &rig,
        &owner,
        marker_program(&marker)
            .gate(Gate::BeforeClone)
            .gate(Gate::BeforeAbandon),
    );
    // The `A` is read and the owner re-check passed; cosca exits before the clone. A copy of the owner
    // keeps the connection, to read what the shim says to a cosca that is gone.
    run.wait_for("gate: waiting at before-clone");
    owner.wait_answered();
    owner.fork_reader();
    owner.kill();
    run.release(Gate::BeforeClone);
    // The shim has seen the owner gone and is about to kill the child: the child must still be held,
    // not released, which is to say the shim still has the write end of the pipe the child waits on.
    run.wait_for("gate: waiting at before-abandon");
    assert!(
        run.holds_the_release_pipe(),
        "the child was released before it was killed"
    );
    run.release(Gate::BeforeAbandon);
    let done = run.finish();
    // The child was created, and held before it armed anything.
    assert!(done.logged("forked child"), "{:#?}", done.lines);
    assert!(done.logged("held child reaped"), "{:#?}", done.lines);
    assert_never_started_after_the_clone(&done, &marker, 123);
    assert_eq!(
        owner.frames(),
        Frame::Refused(Refusal::CoscaGone).encode(),
        "`R`, CoscaGone, and nothing else"
    );
}

#[skuld::test]
fn a_failed_owner_poll_never_reads_as_alive() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut owner = Owner::start("plain");
    let run = owned_by(&rig, &owner, marker_program(&marker).inject(Inject::OwnerPollFails));
    let done = run.finish();
    owner.close_stdin();
    assert_eq!(done.code, Some(117), "{}\n{:#?}", done.stderr, done.lines);
    assert!(
        done.stderr.contains("cannot tell whether cosca is alive"),
        "{}",
        done.stderr
    );
    assert!(!done.logged("forked child"), "{:#?}", done.lines);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn owner_exit_kills_the_program_despite_fd_copies() {
    let rig = ShimRig::new();
    let mut owner = Owner::start("plain");
    let mut run = owned_by(&rig, &owner, Spec::new("cat", &[]).stdin_held());
    run.wait_for("program pid=");
    // A host fork without exec: the copy holds the listener and the connection.
    owner.fork_copy();
    owner.kill();
    // The copy keeps the connection open until here; the shim has to have noticed the owner alone.
    owner.close_stdin();
    let done = run.finish();
    assert!(done.logged("owner exited (armed=true)"), "{:#?}", done.lines);
    assert_eq!(done.code, Some(128 + libc::SIGKILL), "{}", done.stderr);
}

/// A shim held before its loop, with the owner's bytes and exit queued behind it, then released.
fn queued_then_owner_exit(bytes: &str) -> rig::Run {
    let rig = ShimRig::new();
    let mut owner = Owner::start("plain");
    let mut run = owned_by(&rig, &owner, Spec::new("cat", &[]).stdin_held().gate(Gate::BeforeLoop));
    run.wait_for("gate: waiting at before-loop");
    // Everything is queued before the loop's first poll: its first round sees the bytes, the
    // connection's end and the owner's exit together.
    owner.send_and_exit(bytes);
    run.release(Gate::BeforeLoop);
    run
}

#[skuld::test]
fn detach_then_owner_exit_leaves_the_program() {
    let mut run = queued_then_owner_exit("D");
    run.wait_for("owner exited (armed=false)");
    run.close_stdin();
    let done = run.finish();
    assert_eq!(
        done.code,
        Some(0),
        "the program was killed: {}\n{:#?}",
        done.stderr,
        done.lines
    );
    assert!(done.logged("disarmed"), "{:#?}", done.lines);
}

#[skuld::test]
fn queued_control_bytes_all_apply_before_the_owner_exit() {
    let mut run = queued_then_owner_exit("PPD");
    run.wait_count("pong", 2);
    run.wait_for("owner exited (armed=false)");
    run.close_stdin();
    let done = run.finish();
    assert_eq!(
        done.code,
        Some(0),
        "the program was killed: {}\n{:#?}",
        done.stderr,
        done.lines
    );
    // Each byte is served in the order cosca sent it, and the owner's exit comes after all of them.
    let at = |needle: &str| {
        done.lines
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle:?} is not logged: {:#?}", done.lines))
    };
    let pongs: Vec<usize> = done
        .lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.as_str() == "pong")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(pongs.len(), 2, "{:#?}", done.lines);
    assert!(
        pongs[1] < at("disarmed"),
        "the pings come before the `D`: {:#?}",
        done.lines
    );
    assert!(
        at("disarmed") < at("owner exited"),
        "the `D` comes before the owner's exit: {:#?}",
        done.lines
    );
}

#[skuld::test]
fn foreign_writer_of_a_is_refused() {
    // A process holding a copy of the listener accepts the shim and answers `A`: before the shim's
    // checks, and after its hello. Its credentials are not cosca's.
    for mode in ["leak-before", "leak-after"] {
        let rig = ShimRig::new();
        let tmp = tempfile::tempdir().unwrap();
        let marker = tmp.path().join("ran");
        let mut owner = Owner::start(mode);
        let run = owned_by(&rig, &owner, marker_program(&marker));
        let done = run.finish();
        owner.close_stdin();
        assert_never_started(&done, &marker, 122);
        assert!(
            done.logged("the answer was not written by cosca"),
            "{mode}: {:#?}",
            done.lines
        );
    }
}
