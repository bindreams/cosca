//! The test seams that cannot be honoured: the shim stops and says which one, instead of running a
//! test that would then pass without testing anything.

use super::*;
use crate::elevation::shim::hooks::{Gate, Inject};
use crate::shim_env_hooks::{gate_env, CHILD_FAULT_ENV, CHILD_GATE_ENV, INJECT_ENV, LOG_ENV};

/// The shim's exit code and stderr when it panics.
fn panics_with(spec: Spec) -> String {
    let done = ShimRig::new().run_to_end(spec);
    assert_eq!(done.code, Some(101), "a panic: {}\n{:#?}", done.stderr, done.lines);
    done.stderr
}

#[skuld::test]
fn an_injection_that_does_not_exist_panics_naming_it() {
    let stderr = panics_with(Spec::sh("true").raw_seam(INJECT_ENV, "fork-fails,bogus-name"));
    assert!(stderr.contains("bogus-name"), "{stderr}");
    assert!(stderr.contains("not an injection"), "{stderr}");
    // A known name beside it does not excuse it, and each known name is accepted on its own.
    for known in Inject::ALL {
        let spec = Spec::sh("true").raw_seam(INJECT_ENV, known.name());
        let done = ShimRig::new().run_to_end(spec);
        assert_ne!(done.code, Some(101), "{known:?}: {}\n{:#?}", done.stderr, done.lines);
    }
}

#[skuld::test]
fn a_gate_that_cannot_be_opened_panics_naming_the_path() {
    let stderr = panics_with(Spec::sh("true").raw_seam(&gate_env(Gate::BeforeConnect), "/nonexistent/gate"));
    assert!(stderr.contains("/nonexistent/gate"), "{stderr}");
    assert!(stderr.contains(&gate_env(Gate::BeforeConnect)), "{stderr}");
}

#[skuld::test]
fn a_log_that_cannot_be_opened_panics_naming_the_path() {
    let stderr = panics_with(Spec::sh("true").raw_seam(LOG_ENV, "/nonexistent/dir/log"));
    assert!(stderr.contains("/nonexistent/dir/log"), "{stderr}");
}

#[skuld::test]
fn a_child_gate_that_is_not_a_fifo_panics_naming_the_path() {
    let tmp = tempfile::tempdir().unwrap();
    let plain = tmp.path().join("plain");
    std::fs::write(&plain, b"").unwrap();
    let stderr = panics_with(Spec::sh("true").raw_seam(CHILD_GATE_ENV, &plain));
    assert!(stderr.contains(&plain.display().to_string()), "{stderr}");
    let stderr = panics_with(Spec::sh("true").raw_seam(CHILD_GATE_ENV, "/nonexistent/gate"));
    assert!(stderr.contains("/nonexistent/gate"), "{stderr}");
}

#[skuld::test]
fn a_flag_seam_that_is_not_one_panics() {
    let stderr = panics_with(Spec::sh("true").raw_seam(CHILD_FAULT_ENV, "yes"));
    assert!(stderr.contains(CHILD_FAULT_ENV), "{stderr}");
}
