use std::io;

use super::{refusal_state, refused, TargetState};

#[test]
fn a_refusal_is_permission_denied_and_carries_the_target_state() {
    for state in [TargetState::Running, TargetState::Unknown] {
        let err = refused(state, io::Error::from_raw_os_error(1));
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(refusal_state(&err), Some(state));
    }
}

#[test]
fn a_refusal_keeps_the_os_errors_text() {
    let err = refused(TargetState::Running, io::Error::from_raw_os_error(1));
    assert!(err.to_string().contains("os error 1"), "{err}");
}

#[test]
fn other_errors_carry_no_state() {
    assert_eq!(refusal_state(&io::Error::from(io::ErrorKind::PermissionDenied)), None);
    assert_eq!(refusal_state(&io::Error::other("x")), None);
}
