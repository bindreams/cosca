//! Which handles this process holds that a child would inherit, and one `Command` configuration per
//! kind of child end the raw backend makes.

use std::collections::BTreeSet;

use super::handle_snapshot::{walk_handles, OBJ_INHERIT};

/// The values of the handles this process holds with `HANDLE_FLAG_INHERIT` set. The flag comes
/// from one kernel snapshot, so other threads opening or closing handles cannot skew it, and no
/// handle is queried afterwards that a reused value could misreport. A before/after difference
/// of two snapshots still counts an inheritable handle another thread creates in between: callers
/// rely on the test's other threads creating none.
pub fn snapshot() -> BTreeSet<usize> {
    let mut found = BTreeSet::new();
    walk_handles(|h, attributes| {
        if attributes & OBJ_INHERIT != 0 {
            found.insert(h.0 as usize);
        }
    });
    found
}

/// One entry per kind of child end the raw backend makes: the kind's name and the `(slot,
/// target)` pairs that configure it. A slot not listed inherits this process's handle.
pub fn child_end_kinds() -> Vec<(&'static str, Vec<(i32, cosca::Stdio)>)> {
    use cosca::{Fd, Stdio};
    let file = || Stdio::from_file(tempfile::tempfile().expect("tempfile"));
    vec![
        (
            "std pipes",
            vec![(0, Stdio::pipe()), (1, Stdio::pipe()), (2, Stdio::pipe())],
        ),
        (
            "std null",
            vec![(0, Stdio::null()), (1, Stdio::null()), (2, Stdio::null())],
        ),
        (
            "std inherit",
            vec![(0, Stdio::inherit()), (1, Stdio::inherit()), (2, Stdio::inherit())],
        ),
        ("std files", vec![(1, file()), (2, file())]),
        ("std merge", vec![(1, Stdio::pipe()), (2, Stdio::merge(Fd::STDOUT))]),
        ("fd 3 pipe_out", vec![(3, Stdio::pipe_out())]),
        ("fd 3 pipe_in", vec![(3, Stdio::pipe_in())]),
        ("fd 3 null", vec![(3, Stdio::null())]),
        ("fd 3 file", vec![(3, file())]),
        ("fd 3 merge", vec![(1, Stdio::pipe()), (3, Stdio::merge(Fd::STDOUT))]),
    ]
}
