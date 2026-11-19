use std::ffi::{OsStr, OsString};

use super::{CtrlEvent, ProxyAnswer, ProxyArgs, ProxyArgsError, VERSION};

const EXE: &str = "cosca-ctrl-proxy";

fn argv(tail: &[&str]) -> Vec<OsString> {
    std::iter::once(EXE)
        .chain(tail.iter().copied())
        .map(OsString::from)
        .collect()
}

/// Mutant: an event, a pid or the target's key is dropped or swapped on the way through.
#[skuld::test]
fn argv_round_trips_for_both_events() {
    for event in [CtrlEvent::CtrlC, CtrlEvent::CtrlBreak] {
        let args = ProxyArgs {
            target: 4242,
            target_key: 133_000_000_000_000_000,
            event,
            caller: 7,
        };
        let argv = args.to_argv(OsStr::new(EXE));
        assert_eq!(ProxyArgs::parse(&argv), Ok(args), "{argv:?}");
    }
}

/// The wire form is fixed, so a proxy of another build reads it: the version first, as a plain decimal
/// and no flag. Mutant: a flag in front of the version, or another version number.
#[skuld::test]
fn argv_has_the_stated_layout() {
    let args = ProxyArgs {
        target: 4242,
        target_key: 99,
        event: CtrlEvent::CtrlBreak,
        caller: 7,
    };
    assert_eq!(args.to_argv(OsStr::new(EXE)), argv(&["2", "4242", "99", "break", "7"]));
    let args = ProxyArgs {
        event: CtrlEvent::CtrlC,
        ..args
    };
    assert_eq!(args.to_argv(OsStr::new(EXE)), argv(&["2", "4242", "99", "c", "7"]));
    assert_eq!(VERSION, 2);
}

/// Mutant: the version is ignored, or judged after the tail (another version's tail may differ).
#[skuld::test]
fn another_version_is_a_mismatch_whatever_follows() {
    for tail in [
        &["1", "4242", "99", "break", "7"][..],
        &["3"],
        &["3", "x"],
        &["99999", "-1"],
    ] {
        let theirs = tail[0].parse().expect("a number");
        assert_eq!(
            ProxyArgs::parse(&argv(tail)),
            Err(ProxyArgsError::VersionMismatch { ours: VERSION, theirs }),
            "{tail:?}"
        );
    }
}

/// Mutant: a first argument that is no version number is read as a version, or as a tail error.
#[skuld::test]
fn a_first_argument_that_is_no_version_number_is_malformed() {
    for version in [
        "",
        "x",
        "02",
        "+2",
        "-2",
        " 2",
        "2 ",
        "--cosca-ctrl-proxy=2",
        "99999999999",
    ] {
        assert_eq!(
            ProxyArgs::parse(&argv(&[version, "4242", "99", "break", "7"])),
            Err(ProxyArgsError::BadVersion),
            "{version:?}"
        );
    }
}

/// Mutant: an argv with nothing after the program's name is read, or indexes out of range.
#[skuld::test]
fn an_argv_without_a_version_is_the_wrong_count() {
    assert_eq!(ProxyArgs::parse(&argv(&[])), Err(ProxyArgsError::WrongArgumentCount));
    assert_eq!(ProxyArgs::parse(&[]), Err(ProxyArgsError::WrongArgumentCount));
}

/// Mutant: a missing or non-numeric pid or key is read as 0, or a short argv indexes out of range.
#[skuld::test]
fn a_malformed_tail_is_an_error() {
    let version = "2";
    for tail in [
        &[version][..],
        &[version, "4242"],
        &[version, "4242", "99"],
        &[version, "4242", "99", "break"],
        &[version, "4242", "break", "7"],
        &[version, "4242", "99", "break", "7", "extra"],
    ] {
        assert_eq!(
            ProxyArgs::parse(&argv(tail)),
            Err(ProxyArgsError::WrongArgumentCount),
            "{tail:?}"
        );
    }
    for (target, key, caller) in [
        ("", "99", "7"),
        ("x", "99", "7"),
        ("-1", "99", "7"),
        ("+4242", "99", "7"),
        ("04242", "99", "7"),
        ("4294967296", "99", "7"),
        ("4242", "", "7"),
        ("4242", "x", "7"),
        ("4242", "-1", "7"),
        ("4242", "099", "7"),
        ("4242", "18446744073709551616", "7"),
        ("4242", "99", ""),
        ("4242", "99", "y"),
    ] {
        assert_eq!(
            ProxyArgs::parse(&argv(&[version, target, key, "break", caller])),
            Err(ProxyArgsError::BadNumber),
            "{target:?} {key:?} {caller:?}"
        );
    }
    for event in ["", "C", "Break", "ctrl-c", "ctrl_break"] {
        assert_eq!(
            ProxyArgs::parse(&argv(&[version, "4242", "99", event, "7"])),
            Err(ProxyArgsError::BadEvent),
            "{event:?}"
        );
    }
}

/// Mutant: a version mismatch answers as a usage error, or the reverse.
#[skuld::test]
fn errors_answer_by_kind() {
    assert_eq!(
        ProxyArgsError::VersionMismatch { ours: 2, theirs: 3 }.answer(),
        ProxyAnswer::VersionMismatch
    );
    for error in [
        ProxyArgsError::BadVersion,
        ProxyArgsError::WrongArgumentCount,
        ProxyArgsError::BadNumber,
        ProxyArgsError::BadEvent,
    ] {
        assert_eq!(error.answer(), ProxyAnswer::Usage, "{error}");
    }
}

/// Mutant: a code is renumbered, or one is missing from `from_code`.
#[skuld::test]
fn each_answer_has_its_code_and_maps_back() {
    for (answer, code) in [
        (ProxyAnswer::Sent, 150),
        (ProxyAnswer::Usage, 151),
        (ProxyAnswer::VersionMismatch, 152),
        (ProxyAnswer::TargetGone, 153),
        (ProxyAnswer::TargetHasNoConsole, 154),
        (ProxyAnswer::ConsoleIsCallers, 155),
        (ProxyAnswer::NothingSent, 156),
        (ProxyAnswer::AttachDenied, 157),
        (ProxyAnswer::Unconfirmed, 158),
        (ProxyAnswer::NoProxyHere, 159),
        (ProxyAnswer::TargetUnreadable, 160),
    ] {
        assert_eq!(answer.code(), code, "{answer:?}");
        assert_eq!(ProxyAnswer::from_code(code), Some(answer), "{code}");
    }
}

/// Mutant: 0 (a program that is not a proxy, or exits cleanly), a code of the elevation shim (112 to
/// 125) or a Windows `STATUS_CONTROL_C_EXIT` is read as an answer.
#[skuld::test]
fn other_codes_are_not_answers() {
    for code in [0, 1, 100, 110, 117, 120, 125, 149, 161, 0xC000_013A_u32 as i32, -1] {
        assert_eq!(ProxyAnswer::from_code(code), None, "{code}");
    }
}
