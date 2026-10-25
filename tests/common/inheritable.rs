//! Which handles this process holds that a child would inherit, and one `Command` configuration per
//! kind of child end the raw backend makes.

use std::collections::BTreeSet;

use windows::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};

/// The values of the handles this process holds with `HANDLE_FLAG_INHERIT` set. Only meaningful
/// while no other thread opens or closes handles: a handle closed mid-walk makes it run to its
/// bound and assert. That holds under nextest, which runs each test in a process of its own; the
/// suite runs under nothing else.
///
/// It visits every handle value: `GetProcessHandleCount` says how many handles there are, and the
/// walk ends once it has seen that many.
pub fn snapshot() -> BTreeSet<usize> {
    let mut count = 0u32;
    // SAFETY: the pseudo-handle is always valid; `count` is a live out-parameter.
    unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) }.expect("GetProcessHandleCount");
    let (mut remaining, mut found, mut value) = (count, BTreeSet::new(), 0usize);
    while remaining > 0 {
        value += 4;
        // A process holds at most 2^24 handles, each a multiple of 4.
        assert!(value <= 1 << 26, "fewer handles found than the process says it holds");
        let mut flags = 0u32;
        // SAFETY: a value that is not a handle in this process is an error, not UB.
        if unsafe { GetHandleInformation(HANDLE(value as *mut _), &mut flags) }.is_err() {
            continue;
        }
        remaining -= 1;
        if flags & HANDLE_FLAG_INHERIT.0 != 0 {
            found.insert(value);
        }
    }
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
