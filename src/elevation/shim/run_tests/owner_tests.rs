//! cosca's end of the channel going away, and writers that are not cosca.

use super::rig::Owner;
use super::*;
use crate::elevation::shim::hooks::Gate;

/// A shim for `spec`, whose owner is `owner`.
fn owned_by(rig: &ShimRig, owner: &Owner, spec: Spec) -> rig::Run {
    rig.spawn(spec.cosca_pid(owner.pid).dir(&owner.dir))
}

fn assert_never_started(done: &rig::Finished, marker: &Path, code: i32) {
    assert_eq!(done.code, Some(code), "{}\n{:#?}", done.stderr, done.lines);
    assert!(done.stderr.contains(&format!("(exit {code})")), "{}", done.stderr);
    assert!(!done.logged("forked child"), "{:#?}", done.lines);
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
    assert!(done.logged("disarmed"), "{:#?}", done.lines);
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
