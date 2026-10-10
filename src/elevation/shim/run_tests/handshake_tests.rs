//! Who cosca is, and what the shim does when the answer is not `A`.

use super::*;
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::elevation::shim::link::fake_shim::my_euid;
use crate::elevation::shim::link::probe::LinkEvent;
use crate::elevation::shim::link::KillOutcome;
use crate::test_groups::{namespaces, Group};

/// The shim's stderr lines.
fn stderr_lines(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|l| !l.is_empty()).collect()
}

/// Runs `spec` held after it connects until cosca has accepted it, and returns its end.
fn run_after_accept(rig: &ShimRig, spec: Spec) -> rig::Finished {
    let mut run = rig.spawn(spec.gate(Gate::BeforeIdentity));
    rig.link.expect_event(LinkEvent::Accepted);
    run.release(Gate::BeforeIdentity);
    run.finish()
}

#[skuld::test]
fn wrong_identity_is_refused_before_hello_and_not_started() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    // The listener is this process, whatever argv says.
    let done = run_after_accept(&rig, marker_program(&marker).cosca_pid(std::process::id() ^ 1));
    assert_eq!(done.code, Some(122), "{}", done.stderr);
    assert_eq!(stderr_lines(&done.stderr).len(), 1, "{}", done.stderr);
    assert!(done.stderr.contains("(exit 122)"), "{}", done.stderr);
    assert!(!done.logged("hello sent"), "{:#?}", done.lines);
    assert_eq!(rig.link.link.wait().unwrap(), not_started_unconnected());
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn missing_proc_is_refused_and_says_proc_must_be_mounted(#[fixture(namespaces)] _group: &Group) {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let done = rig.run_to_end(marker_program(&marker).without_proc());
    assert_eq!(done.code, Some(124), "{}\n{:#?}", done.stderr, done.lines);
    assert!(done.stderr.contains("/proc must be mounted"), "{}", done.stderr);
    assert!(!done.stderr.contains("could not reach cosca"), "{}", done.stderr);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn wrong_euid_is_refused() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let done = run_after_accept(&rig, marker_program(&marker).cosca_euid(my_euid() + 1));
    assert_eq!(done.code, Some(122), "{}", done.stderr);
    assert!(!done.logged("hello sent"), "{:#?}", done.lines);
    assert_eq!(rig.link.link.wait().unwrap(), not_started_unconnected());
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn answer_n_never_starts_the_program() {
    let rig = ShimRig::new();
    let tmp = tempfile::tempdir().unwrap();
    let marker = tmp.path().join("ran");
    let mut run = rig.spawn(marker_program(&marker).gate(Gate::BeforeIdentity));
    rig.link.expect_event(LinkEvent::Accepted);
    // The start is refused while the shim is queued: it will be answered `N`.
    assert_eq!(rig.link.link.kill().unwrap(), KillOutcome::RefusedStart);
    run.release(Gate::BeforeIdentity);
    let done = run.finish();
    assert_eq!(done.code, Some(125), "{}", done.stderr);
    assert!(done.logged("first byte: N"), "{:#?}", done.lines);
    assert!(done.stderr.contains("(exit 125)"), "{}", done.stderr);
    assert!(!done.logged("forked child"), "{:#?}", done.lines);
    assert!(!marker.exists(), "the program ran");
}

#[skuld::test]
fn owner_pidfd_emfile_is_116_not_123() {
    let rig = ShimRig::new();
    let done = run_after_accept(&rig, Spec::sh("true").exhaust_fds());
    assert_eq!(done.code, Some(116), "{}", done.stderr);
    assert!(done.stderr.contains("(exit 116)"), "{}", done.stderr);
    assert!(done.logged("pidfd_open(owner)"), "{:#?}", done.lines);
    assert_eq!(rig.link.link.wait().unwrap(), not_started_unconnected());
}

#[skuld::test]
fn refusal_codes_and_stderr_lines() {
    // (spec, exit code, whether one stderr line names it). Pre-fork codes write one line;
    // post-fork outcomes write none.
    let rig_for = |spec: Spec, code: i32, line: bool| {
        let rig = ShimRig::new();
        let done = rig.run_to_end(spec);
        assert_eq!(done.code, Some(code), "{}", done.stderr);
        let lines = stderr_lines(&done.stderr);
        if line {
            assert_eq!(lines.len(), 1, "code {code}: {}", done.stderr);
            assert!(lines[0].contains(&format!("(exit {code})")), "{}", done.stderr);
        } else {
            assert!(lines.is_empty(), "code {code}: {}", done.stderr);
        }
    };
    let nowhere = tempfile::tempdir().unwrap();
    rig_for(Spec::sh("true").flag("--cosca-elevation-shim=2"), 120, true);
    rig_for(Spec::sh("true").cosca_pid(std::process::id() ^ 1), 122, true);
    rig_for(Spec::sh("true").dir(&nowhere.path().join("gone")), 124, true);
    rig_for(Spec::sh("true").exhaust_fds(), 116, true);
    rig_for(
        Spec::new("no-such-program", &[]).search_path("/usr/bin:/bin"),
        117,
        true,
    );
    rig_for(Spec::sh("true").inject(Inject::ForkFails), 117, true);
    rig_for(Spec::sh("true").inject(Inject::PipeFails), 117, true);
    // After the fork: the status pipe's report, and the program's own status.
    rig_for(Spec::new("/nonexistent/tool", &[]), 117, false);
    rig_for(Spec::sh("exit 3"), 3, false);
}
