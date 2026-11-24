use std::ffi::{OsStr, OsString};

use std::num::NonZeroU16;

use super::{Cause, CtrlEvent, ProxyAnswer, ProxyArgs, ProxyArgsError, ProxyExit, Step, VERSION};

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
    assert_eq!(args.to_argv(OsStr::new(EXE)), argv(&["4", "4242", "99", "break", "7"]));
    let args = ProxyArgs {
        event: CtrlEvent::CtrlC,
        ..args
    };
    assert_eq!(args.to_argv(OsStr::new(EXE)), argv(&["4", "4242", "99", "c", "7"]));
    assert_eq!(VERSION, 4);
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
    let version = "4";
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
        (ProxyAnswer::AttachDenied, 157),
        (ProxyAnswer::Unconfirmed, 158),
        (ProxyAnswer::NoProxyHere, 159),
    ] {
        assert_eq!(answer.code(), code, "{answer:?}");
        assert_eq!(ProxyAnswer::from_code(code), Some(answer), "{code}");
        assert_eq!(ProxyExit::from_code(code), Some(ProxyExit::Answer(answer)), "{code}");
        assert_eq!(ProxyExit::from(answer).code(), code);
    }
}

/// Mutant: 0 (a program that is not a proxy, or exits cleanly), a code of the elevation shim (112 to
/// 125), a Windows `STATUS_CONTROL_C_EXIT`, or 156 or 160 (left unused: a failed step exits with its
/// cause) is read as an exit of the protocol.
#[skuld::test]
fn other_codes_are_not_exits() {
    for code in [
        0,
        1,
        100,
        110,
        117,
        120,
        125,
        149,
        156,
        160,
        161,
        0xC000_013A_u32 as i32,
        -1,
    ] {
        assert_eq!(ProxyAnswer::from_code(code), None, "{code}");
        assert_eq!(ProxyExit::from_code(code), None, "{code}");
    }
}

/// Mutant: a field of the cause code is shifted onto another, a step is lost, or a code is cut.
#[skuld::test]
fn a_cause_round_trips_for_every_step_with_and_without_a_code() {
    for step in Step::ALL {
        for code in [None, Some(5), Some(1450), Some(0xFFFF)] {
            let cause = Cause::new(step, code);
            assert_eq!(cause.os_code.map(|c| i32::from(c.get())), code, "{cause:?}");
            let exit = cause.code();
            assert_eq!(Cause::from_code(exit), Some(cause), "{cause:?} {exit:#x}");
            assert_eq!(ProxyExit::from_code(exit), Some(ProxyExit::Cause(cause)), "{exit:#x}");
            assert_eq!(ProxyExit::Cause(cause).code(), exit);
        }
    }
}

/// Each step has its number and says whether the event had been generated when it failed: only the wait after the
/// generate says so. Mutant: a step is renumbered, the wait says "not generated", or the generate says "generated".
#[skuld::test]
fn each_step_has_its_number_and_says_whether_the_event_was_generated() {
    let table = [
        (Step::TargetIdentity, 1, false),
        (Step::OpenTarget, 2, false),
        (Step::FreeConsole, 3, false),
        (Step::AttachConsole, 4, false),
        (Step::ReenableCtrlC, 5, false),
        (Step::ConsoleProcessList, 6, false),
        (Step::CreateEvent, 7, false),
        (Step::InstallHandler, 8, false),
        (Step::ResetEvent, 9, false),
        (Step::ConsoleClosing, 10, false),
        (Step::Generate, 11, false),
        (Step::WaitForOwnCopy, 12, true),
    ];
    assert_eq!(table.map(|(step, ..)| step), Step::ALL);
    for (step, number, generated) in table {
        assert_eq!(step as i32, number, "{step:?}");
        assert_eq!(step.event_generated(), generated, "{step:?}");
    }
}

/// A failed wait exits with its step in bits 17 to 23 and its Win32 code in the low 16 bits. Mutant: the step
/// or the code field sits at other bits than the layout says.
#[skuld::test]
fn a_failed_wait_exits_with_its_step_and_win32_code() {
    let cause = Cause::new(Step::WaitForOwnCopy, Some(6));
    assert_eq!(cause.code(), 0x2000_0000 | (12 << 17) | 0x1_0000 | 6);
    assert_eq!(ProxyExit::from_code(cause.code()), Some(ProxyExit::Cause(cause)));
}

/// The proxy's stderr line says an answer by name and a failed step by whether the event had been generated;
/// a `Sent` answer prints nothing. Mutant: the two phrasings of a failed step are swapped, or `Sent` prints.
#[cfg(windows)]
#[skuld::test]
fn the_stderr_line_words_an_exit_by_whether_the_event_was_generated() {
    assert_eq!(ProxyExit::Answer(ProxyAnswer::Sent).stderr_line(), None);
    assert_eq!(
        ProxyExit::Answer(ProxyAnswer::Unconfirmed).stderr_line().as_deref(),
        Some("answering Unconfirmed (exit 158)")
    );
    let wait = ProxyExit::Cause(Cause::new(Step::WaitForOwnCopy, Some(6)));
    assert_eq!(
        wait.stderr_line().as_deref(),
        Some("failed a step, the event was generated: Cause { step: WaitForOwnCopy, os_code: Some(6) } (exit 0x20190006)")
    );
    let before = ProxyExit::Cause(Cause::new(Step::Generate, None));
    assert_eq!(
        before.stderr_line().as_deref(),
        Some("failed a step, nothing sent: Cause { step: Generate, os_code: None } (exit 0x20160000)")
    );
}

/// Only an OS code of 1 to 0xFFFF travels; the step travels whatever the error was. Mutants: 0 is kept
/// as a code, a wider code is truncated into another one, or a negative one (a non-Win32 HRESULT that
/// `win32_io_error` keeps whole) gives a code.
#[skuld::test]
fn only_a_win32_code_of_16_bits_travels() {
    let step = Step::AttachConsole;
    for (code, travels) in [
        (0, None),
        (1, Some(1)),
        (5, Some(5)),
        (0xFFFF, Some(0xFFFF)),
        (0x1_0000, None),
        (i32::MAX, None),
        (-1, None),
        (0x8000_4005_u32 as i32, None),
    ] {
        let cause = Cause::new(step, Some(code));
        assert_eq!(cause.os_code, travels.and_then(NonZeroU16::new), "{code:#x}");
    }
    assert_eq!(Cause::new(step, None).os_code, None);
}

/// A cause code is a positive `i32` with the customer bit set and no crash status, and no cause code is
/// an answer or the unknown-role code. Mutant: a layout that sets bit 31 or 30, or reaches 100 or an
/// answer (150 to 159; 156 and 160 are unused).
#[skuld::test]
fn a_cause_code_collides_with_nothing() {
    for step in Step::ALL {
        for os_code in [None, Some(1), Some(0xFFFF)] {
            let code = Cause::new(step, os_code).code();
            assert!(code > 0, "positive: {code:#x}");
            assert_eq!(code & 0x2000_0000, 0x2000_0000, "customer bit: {code:#x}");
            assert_eq!(code & 0x4000_0000, 0, "{code:#x}");
            assert_eq!(ProxyAnswer::from_code(code), None, "{code:#x}");
            assert_ne!(code, crate::role::UNKNOWN_HELPER_ROLE);
        }
    }
    assert_eq!(ProxyExit::from_code(crate::role::UNKNOWN_HELPER_ROLE), None);
}

/// A value of the cause field's range that is no cause is no exit of the protocol. Mutant: the decoder
/// ignores one of the checks the cases name.
#[skuld::test]
fn a_malformed_cause_code_is_no_exit() {
    let valid = Cause::new(Step::AttachConsole, Some(5)).code();
    let no_code = Cause::new(Step::AttachConsole, None).code();
    for bad in [
        valid ^ 0x2000_0000,
        valid | 0x4000_0000,
        valid | i32::MIN,
        valid | 0x0100_0000,
        valid | 0x1000_0000,
        // Step 0, the first number past the last step, and the widest field.
        0x2000_0000,
        0x2000_0000 | 0x1_0000,
        0x2000_0000 | (13 << 17),
        0x2000_0000 | (0x7F << 17),
        // A code with its flag clear has one spelling only: none.
        no_code | 5,
        // And so has a code of 0: the flag clear.
        no_code | 0x1_0000,
    ] {
        assert_eq!(Cause::from_code(bad), None, "{bad:#x}");
        assert_eq!(ProxyExit::from_code(bad), None, "{bad:#x}");
    }
}

/// Answers and small codes are decimal; a cause, a malformed cause-range value and an NTSTATUS (negative as an
/// `i32`) are hex. Mutant: a code in the other base, or the marker's own value read as small.
#[skuld::test]
fn an_exit_code_is_shown_in_decimal_unless_it_is_a_bit_pattern() {
    for (code, shown) in [
        (0, "0"),
        (ProxyAnswer::Sent.code(), "150"),
        (ProxyAnswer::NoProxyHere.code(), "159"),
        (156, "156"),
        (3, "3"),
        (0x1FFF_FFFF, "536870911"),
        (Cause::new(Step::AttachConsole, Some(5)).code(), "0x20090005"),
        (0x2000_0000, "0x20000000"),
        (0xC000_013A_u32 as i32, "0xc000013a"),
        (-1, "0xffffffff"),
    ] {
        assert_eq!(super::exit_text(code), shown, "{code}");
    }
}
