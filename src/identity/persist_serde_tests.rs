//! The persisted wire format. These literals ARE the format: a change here is a change
//! every already-written record has to survive, so the expected JSON is written by hand
//! from the documented format, never captured from the code's own output.

#![cfg(feature = "serde")]

use super::{Platform, ProcessIdRecord, RECORD_VERSION};

fn windows_record() -> ProcessIdRecord {
    ProcessIdRecord {
        version: 1,
        platform: Platform::Windows,
        pid: 4242,
        // A real measured creation FILETIME, larger than 2^53.
        token: 134_301_578_477_907_396,
        boot_id: None,
        pid_ns: None,
    }
}

fn linux_record() -> ProcessIdRecord {
    ProcessIdRecord {
        version: 1,
        platform: Platform::Linux,
        pid: 4242,
        token: 162_431_157,
        boot_id: Some("36c39237-f06e-4e88-a74d-ea99d42b817c".into()),
        pid_ns: Some(4_026_531_836),
    }
}

#[test]
fn the_version_is_one() {
    // The wire literals below hard-code v1; a bump must come with a format decision.
    assert_eq!(RECORD_VERSION, 1);
}

#[test]
fn a_windows_record_serializes_to_the_documented_json() {
    let json = serde_json::to_string(&windows_record()).expect("serialize");
    assert_eq!(
        json,
        r#"{"v":1,"platform":"windows","pid":4242,"token":"134301578477907396"}"#
    );
}

#[test]
fn a_linux_record_serializes_to_the_documented_json() {
    let json = serde_json::to_string(&linux_record()).expect("serialize");
    assert_eq!(
        json,
        r#"{"v":1,"platform":"linux","pid":4242,"token":"162431157","boot_id":"36c39237-f06e-4e88-a74d-ea99d42b817c","pid_ns":4026531836}"#
    );
}

#[test]
fn the_token_survives_json_without_precision_loss() {
    // Windows tokens exceed 2^53 (9007199254740992), so a JSON *number* would be corrupted
    // by any consumer with double-precision numbers. It is a decimal string on the wire.
    assert!(windows_record().token > 9_007_199_254_740_992);
    let json = serde_json::to_string(&windows_record()).expect("serialize");
    let back: ProcessIdRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.token, 134_301_578_477_907_396);
    assert_eq!(back, windows_record());
}

#[test]
fn records_round_trip_through_json() {
    for r in [windows_record(), linux_record()] {
        let json = serde_json::to_string(&r).expect("serialize");
        let back: ProcessIdRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, r);
    }
}

#[test]
fn an_unknown_platform_tag_decodes_rather_than_failing() {
    // Forward compatibility: a record from a newer cosca on a platform this build does not
    // know must reach VALIDATION (which rejects it with a reason), not die in the decoder.
    let json = r#"{"v":1,"platform":"freebsd","pid":7,"token":"99"}"#;
    let r: ProcessIdRecord = serde_json::from_str(json).expect("an unknown tag must still decode");
    assert_eq!(r.platform, Platform::Other("freebsd".into()));
}

#[test]
fn an_unknown_version_decodes_rather_than_failing() {
    let json = r#"{"v":999,"platform":"linux","pid":7,"token":"99"}"#;
    let r: ProcessIdRecord = serde_json::from_str(json).expect("an unknown version must still decode");
    assert_eq!(r.version, 999);
}

#[test]
fn unknown_fields_are_ignored() {
    // A v1 reader must tolerate additive fields from a later writer well enough to reach
    // the version check.
    let json = r#"{"v":1,"platform":"linux","pid":7,"token":"99","boot_id":"b","pid_ns":1,"future":42}"#;
    let r: ProcessIdRecord = serde_json::from_str(json).expect("deserialize");
    assert_eq!(r.pid, 7);
}

#[test]
fn a_non_numeric_token_string_is_a_decode_error() {
    let json = r#"{"v":1,"platform":"linux","pid":7,"token":"not-a-number"}"#;
    assert!(serde_json::from_str::<ProcessIdRecord>(json).is_err());
}

#[test]
fn a_foreign_platform_record_is_refused_after_a_json_round_trip() {
    // Cross-platform rejection driven entirely through the wire format, on whatever host
    // this test runs on: the record names the OTHER platform, so it must never restore.
    use crate::identity::ProcessId;
    let foreign = if cfg!(windows) {
        linux_record()
    } else {
        windows_record()
    };
    let json = serde_json::to_string(&foreign).expect("serialize");
    let decoded: ProcessIdRecord = serde_json::from_str(&json).expect("deserialize");
    match ProcessId::try_from(&decoded) {
        Err(crate::error::Error::IdentityRecord { kind, .. }) => {
            assert_eq!(kind, crate::error::RecordErrorKind::ForeignPlatform)
        }
        other => panic!("expected ForeignPlatform, got {other:?}"),
    }
}

#[test]
fn a_newer_version_record_is_refused_after_a_json_round_trip() {
    // Version is checked FIRST, before platform, precisely because a future format may
    // reuse these fields with different meanings — so the record below names THIS platform
    // and is otherwise well-formed, leaving the version as the only reason to refuse it.
    use crate::identity::ProcessId;
    let mut newer = if cfg!(windows) {
        windows_record()
    } else {
        linux_record()
    };
    newer.version = RECORD_VERSION + 1;
    newer.platform = Platform::current();
    let json = serde_json::to_string(&newer).expect("serialize");
    let decoded: ProcessIdRecord = serde_json::from_str(&json).expect("a newer version must still decode");
    match ProcessId::try_from(&decoded) {
        Err(crate::error::Error::IdentityRecord { kind, .. }) => {
            assert_eq!(kind, crate::error::RecordErrorKind::UnknownVersion)
        }
        other => panic!("expected UnknownVersion, got {other:?}"),
    }
}

#[test]
fn a_live_identity_survives_a_json_round_trip_on_this_host() {
    use crate::identity::ProcessId;
    let me = ProcessId::current();
    let json = serde_json::to_string(&me.to_record().expect("to_record")).expect("serialize");
    let decoded: ProcessIdRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ProcessId::try_from(&decoded).expect("restore"), me);
}
