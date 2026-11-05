//! `Drop` of a `TreeWalk` child whose process snapshot the kernel refuses (a real seccomp filter on
//! `openat2`). In the library, not `tests/`: the release hook below bounds the drop's wait, so a
//! drop that kills nothing fails an assertion instead of hanging on a held pipe.

use crate::identity::Existence;
use crate::test_seccomp::{deny_openat2_on_this_thread, OPENAT2_REFUSALS};

/// `Drop` cannot retry, so it still kills the root through its handle, and says descendants may be
/// orphaned.
#[skuld::test]
fn a_seccomp_refused_openat2_makes_a_treewalk_drop_kill_the_root_and_warn_of_orphans() {
    crate::log_capture::install();
    for (errno, name) in OPENAT2_REFUSALS {
        let id = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let mark = crate::log_capture::mark();
                    let (child, stdin) = crate::test_child::held_treewalk_blocker();
                    assert_eq!(child.containment(), crate::containment::Containment::TreeWalk);
                    let blocker = crate::child::spawn::fault::release_at_drop_kill(stdin);
                    let id = child.id();
                    deny_openat2_on_this_thread(errno);
                    drop(child);
                    let records = crate::log_capture::records_since_on_current_thread(mark, "Child::drop");
                    assert!(
                        records
                            .iter()
                            .any(|(level, m)| *level == log::Level::Warn && m.contains("may be orphaned")),
                        "{name}: {records:?}"
                    );
                    blocker.assert_killed();
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
