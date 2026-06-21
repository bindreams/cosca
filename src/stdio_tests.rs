use super::{Direction, Fd, ResolvedStdio, Stdio};
use crate::error::Error;

#[test]
fn fd_consts_and_from_int() {
    assert_eq!(Fd::STDIN.raw(), 0);
    assert_eq!(Fd::STDOUT.raw(), 1);
    assert_eq!(Fd::STDERR.raw(), 2);
    assert_eq!(Fd::from(3).raw(), 3);
}

#[test]
fn fd_display() {
    assert_eq!(Fd::STDIN.to_string(), "stdin");
    assert_eq!(Fd::STDOUT.to_string(), "stdout");
    assert_eq!(Fd::STDERR.to_string(), "stderr");
    assert_eq!(Fd::from(7).to_string(), "fd 7");
}

#[test]
fn pipe_direction_inferred_from_std_slots() {
    assert!(matches!(
        Stdio::pipe().resolve(Fd::STDIN).unwrap(),
        ResolvedStdio::Pipe(Direction::In)
    ));
    assert!(matches!(
        Stdio::pipe().resolve(Fd::STDOUT).unwrap(),
        ResolvedStdio::Pipe(Direction::Out)
    ));
    assert!(matches!(
        Stdio::pipe().resolve(Fd::STDERR).unwrap(),
        ResolvedStdio::Pipe(Direction::Out)
    ));
}

#[test]
fn explicit_pipe_direction_passes_through_on_any_slot() {
    assert!(matches!(
        Stdio::pipe_in().resolve(Fd::from(3)).unwrap(),
        ResolvedStdio::Pipe(Direction::In)
    ));
    assert!(matches!(
        Stdio::pipe_out().resolve(Fd::from(9)).unwrap(),
        ResolvedStdio::Pipe(Direction::Out)
    ));
}

#[test]
fn bare_pipe_on_arbitrary_fd_is_unsupported() {
    let err = Stdio::pipe().resolve(Fd::from(3)).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}

#[test]
fn inherit_null_merge_resolve() {
    assert!(matches!(
        Stdio::inherit().resolve(Fd::STDOUT).unwrap(),
        ResolvedStdio::Inherit
    ));
    assert!(matches!(Stdio::null().resolve(Fd::STDIN).unwrap(), ResolvedStdio::Null));
    assert!(
        matches!(Stdio::merge(Fd::STDOUT).resolve(Fd::STDERR).unwrap(), ResolvedStdio::Merge(f) if f == Fd::STDOUT)
    );
}

#[cfg(feature = "pty")]
#[test]
fn pty_resolves_to_unsupported() {
    let err = Stdio::pty().resolve(Fd::STDIN).unwrap_err();
    assert!(matches!(err, Error::Unsupported { .. }), "{err:?}");
}
