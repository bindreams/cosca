//! `Unreaped`'s contract, on a child held as a spawn teardown holds it: `wait` reaps and returns
//! the status, `leak` gives the child up unreaped, and `Drop` blocks until the child exits.

use super::{Held, Unreaped};
use crate::identity::{ProcessId, Resolved};

/// A child blocked reading stdin until the returned end drops, and its identity.
fn blocked_child() -> (std::process::Child, std::process::ChildStdin, ProcessId) {
    let mut child = {
        // Raw std bypasses cosca's spawn path and its internal `spawn_lock()`, so it is taken here
        // by hand: a macOS fork must not transiently inherit another test's fd-marker write end.
        let _guard = crate::child::spawn::spawn_lock();
        let mut cmd = if cfg!(windows) {
            let mut cmd = std::process::Command::new("findstr");
            cmd.arg("x");
            cmd
        } else {
            std::process::Command::new("cat")
        };
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child blocked on stdin")
    };
    let stdin = child.stdin.take().expect("piped stdin");
    let Resolved::Found(id) = ProcessId::of(child.id()) else {
        panic!("an unreaped child resolves");
    };
    (child, stdin, id)
}

#[test]
fn wait_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    assert_eq!(unreaped.pid(), id.pid());
    drop(stdin);
    let status = unreaped.wait().expect("wait for the child");
    // Its own exit, on end of input: `cat` succeeds, and `findstr` finds no match.
    assert_eq!(status.code(), Some(if cfg!(windows) { 1 } else { 0 }), "{status:?}");
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `Drop` waits: the child is still running when the `Unreaped` drops, and reaped once it returns
/// — a `Drop` that did not wait would leave it running, or a zombie still holding its identity.
#[test]
fn drop_blocks_until_the_child_exits_and_reaps_it() {
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    drop(stdin);
    drop(unreaped);
    crate::child::spawn::fault::assert_child_reaped(Resolved::Found(id));
}

/// `leak` gives the child up without reaping it, and says so: here the child, once it exits, is
/// still this process's to reap, which only an unreaped child is.
#[cfg(unix)]
#[test]
fn leak_gives_the_child_up_unreaped_and_logs_it() {
    crate::log_capture::install();
    let (child, stdin, id) = blocked_child();
    let unreaped = Unreaped::new(Held::Std(child));
    let mark = crate::log_capture::mark();
    unreaped.leak();
    assert!(
        crate::log_capture::contains_since(mark, &format!("leaking unkillable child {}", id.pid())),
        "a leak must be logged"
    );
    drop(stdin);
    let pid = nix::unistd::Pid::from_raw(id.pid() as i32);
    nix::sys::wait::waitpid(pid, None).expect("a leaked child is left unreaped");
}
