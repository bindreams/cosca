//! Tests of `exit_only`'s Linux backend over real children: the contract breach of its blocking
//! wait.

use crate::os_process::child::adopted_blocker;
use crate::test_child::wait_until_zombie;
use crate::wait::exit_only::seams as exit_seams;
use crate::wait::exit_only::Target;

// A blocking `waitid` that finds no record =====

/// A blocking `waitid` that finds no record is a contract breach, not a ptrace stop: it asserts in
/// a debug build and is an error in a release build, never a `Running` a caller loops on.
///
/// Mutant: `Ok(None)` folded into the non-exit arm, which answers `Running`.
#[skuld::test]
fn a_blocking_waitid_that_finds_no_record_is_a_contract_breach() {
    let (os, id, stdin) = adopted_blocker();
    drop(stdin);
    wait_until_zombie(id.pid());
    let target = Target::PidFd(os.os_handle());
    let forced = exit_seams::force_visible_none_once();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::wait::exit_only::wait_visible_exit(&target)
    }));
    drop(forced);
    if cfg!(debug_assertions) {
        assert!(outcome.is_err(), "a debug build asserts the contract");
    } else {
        let err = outcome.expect("release returns").expect_err("a breach is an error");
        assert!(err.to_string().contains("no record"), "{err}");
    }
}
