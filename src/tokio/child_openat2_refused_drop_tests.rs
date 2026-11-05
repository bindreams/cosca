//! The async twin of `child/openat2_refused_drop_tests.rs`.

use crate::identity::Existence;
use crate::test_seccomp::{deny_openat2_on_this_thread, OPENAT2_REFUSALS};

/// The drop waits for the root, so its stdin is released between the drop's kill and its wait
/// (`release_between_kill_and_wait`): a root nothing killed exits `0` on the release, and the reap's
/// recorded status then fails the `SIGKILL` assertion instead of leaving the drop waiting.
///
/// Mutant: the async drop skips the root kill after a snapshot failure.
#[skuld::test]
fn a_seccomp_refused_openat2_makes_an_async_treewalk_drop_kill_the_root_and_warn_of_orphans() {
    crate::log_capture::install();
    for (errno, name) in OPENAT2_REFUSALS {
        // The filter ends with its thread, so the assertion on `id` below still has `openat2`.
        let id = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    // The seams are thread-local: the runtime must poll nothing on another thread.
                    let runtime = ::tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("a current-thread runtime");
                    let _entered = runtime.enter();
                    let mark = crate::log_capture::mark();
                    let (child, stdin) = crate::test_child::held_treewalk_blocker_async();
                    assert_eq!(child.containment(), crate::containment::Containment::TreeWalk);
                    let released = crate::child::spawn::fault::release_between_kill_and_wait(stdin);
                    let id = child.id();
                    let sends = crate::send_log::Capture::start();
                    deny_openat2_on_this_thread(errno);
                    drop(child);
                    let records = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
                    assert!(
                        records
                            .iter()
                            .any(|(level, m)| *level == log::Level::Warn && m.contains("may be orphaned")),
                        "{name}: {records:?}"
                    );
                    released.assert_killed();
                    assert!(
                        sends
                            .entries()
                            .contains(&(id.pid(), crate::signal::Sig::Kill, crate::send_log::Via::Pidfd)),
                        "{name}: the root must be killed through its pidfd: {:?}",
                        sends.entries()
                    );
                    id
                })
                .join()
                .expect("the filtered thread")
        });
        assert_eq!(
            id.exists(),
            Existence::Gone,
            "{name}: the root must be killed and reaped"
        );
    }
}
