//! The shim process against a real [`ShimLink`](super::link::ShimLink), as the same uid. The
//! lib's test binary is the shim: its `main` calls `init_with_test_hooks`.

use std::path::{Path, PathBuf};

use crate::elevation::shim::link::{LinkOutcome, NotStarted, NotStartedCause};
use rig::{ShimRig, Spec};

#[path = "run_tests/edge_tests.rs"]
mod edge_tests;
#[path = "run_tests/handshake_tests.rs"]
mod handshake_tests;
#[path = "run_tests/outcome_tests.rs"]
mod outcome_tests;
#[path = "run_tests/owner_tests.rs"]
mod owner_tests;
#[path = "run_tests/program_tests.rs"]
mod program_tests;
#[path = "run_tests/rig.rs"]
mod rig;
#[path = "run_tests/signal_tests.rs"]
mod signal_tests;

/// A program that records that it ran, and so can be checked not to have.
fn marker_program(marker: &Path) -> Spec {
    Spec::new(
        "/bin/sh",
        &["-c", "echo ran > \"$1\"", "sh", marker.to_str().expect("a UTF-8 path")],
    )
}

/// The outcome of a shim that never said hello.
fn not_started_unconnected() -> LinkOutcome {
    LinkOutcome::NotStarted(NotStarted {
        shim_connected: false,
        cause: NotStartedCause::Withheld,
    })
}
