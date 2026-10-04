use std::os::fd::{AsRawFd, OwnedFd};

use super::{above_stdio, above_stdio_keeping};

fn pipe() -> (OwnedFd, OwnedFd) {
    let (r, w) = std::io::pipe().expect("pipe");
    (OwnedFd::from(r), OwnedFd::from(w))
}

fn is_cloexec(fd: &OwnedFd) -> bool {
    // SAFETY: `fcntl` on an fd the caller owns.
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC != 0 }
}

/// A descriptor already at 3 or above is returned as it is.
///
/// Mutant: it is always duplicated.
#[skuld::test]
fn a_descriptor_above_stdio_stays() {
    let (r, _w) = pipe();
    let at = r.as_raw_fd();
    assert!(at >= 3);
    assert_eq!(above_stdio(r).expect("above stdio").as_raw_fd(), at);
}

/// With stdio closed the lowest free numbers are stdio slots; the descriptor moves to 3 or above
/// and is close-on-exec. Runs in a re-exec'd child.
///
/// Mutant: `above_stdio` returns its argument unchanged.
#[skuld::test]
fn a_descriptor_in_a_stdio_slot_moves_above_it() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(fixture_above_stdio_with_stdio_closed));
}

#[skuld::test]
fn fixture_above_stdio_with_stdio_closed() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let saved = crate::test_child::close_stdio_keeping_a_copy();
    let (r, w) = pipe();
    let low = (r.as_raw_fd(), w.as_raw_fd());
    let moved = above_stdio(r);
    let outcome = moved
        .as_ref()
        .map(|fd| (fd.as_raw_fd(), is_cloexec(fd)))
        .map_err(ToString::to_string);
    drop(moved);
    drop(w);
    drop(saved);
    assert!(
        low.0 < 3 && low.1 < 3,
        "the precondition: the pipe landed in stdio slots {low:?}"
    );
    let (at, cloexec) = outcome.expect("the move succeeds");
    assert!(at >= 3, "moved to {at}");
    assert!(cloexec, "close-on-exec");
}

/// A move that fails hands the descriptor back, still in its slot. Runs in a re-exec'd child with
/// the descriptor limit too low for any number from 3 up.
///
/// Mutant: the descriptor is dropped when its move fails.
#[skuld::test]
fn a_failed_move_hands_the_descriptor_back() {
    crate::test_child::run_fixture(crate::test_child::fixture_path!(
        fixture_above_stdio_keeping_at_the_limit
    ));
}

#[skuld::test]
fn fixture_above_stdio_keeping_at_the_limit() {
    if !crate::test_child::is_fixture_reexec() {
        return;
    }
    let saved = crate::test_child::close_stdio_keeping_a_copy();
    let (r, w) = pipe();
    let low = r.as_raw_fd();
    let limit = libc::rlimit {
        rlim_cur: 3,
        rlim_max: 3,
    };
    // SAFETY: lowers this fixture process's own descriptor limit.
    let set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    let kept = above_stdio_keeping(r);
    let outcome = match &kept {
        Ok(_) => None,
        Err((_, fd)) => Some(fd.as_raw_fd()),
    };
    drop(kept);
    drop(w);
    drop(saved);
    assert_eq!(set, 0, "lower the limit");
    assert!(low < 3, "the precondition: the pipe landed in a stdio slot");
    assert_eq!(outcome, Some(low), "the failed move hands the same descriptor back");
}
