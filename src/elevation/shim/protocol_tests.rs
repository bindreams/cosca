use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::{
    decode_frame, to_hex, Command, Errno, Frame, FrameError, NotExecuted, Refusal, ShimArgs, ShimArgsError,
    ShimIdentity, Signal, UnknownCommand,
};

const EXE: &str = "/opt/host/app";

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn identity() -> ShimIdentity {
    ShimIdentity {
        unique_id: u64::MAX,
        id_version: u32::MAX,
    }
}

/// This platform's identity: present exactly on macOS.
fn platform_identity() -> Option<ShimIdentity> {
    cfg!(target_os = "macos").then(identity)
}

fn args(program: &[u8], rest: &[&[u8]]) -> ShimArgs {
    ShimArgs {
        dir: PathBuf::from("/tmp/cosca-x1"),
        cosca_pid: 4242,
        cosca_identity: platform_identity(),
        cosca_euid: 1000,
        search_path: None,
        program: os(program),
        args: rest.iter().map(|a| os(a)).collect(),
    }
}

fn argv(a: &ShimArgs, hex: bool) -> Vec<OsString> {
    a.to_argv(OsStr::new(EXE), hex)
}

fn parsed(a: &ShimArgs, hex: bool) -> ShimArgs {
    ShimArgs::parse(&argv(a, hex)).unwrap().unwrap()
}

/// `argv` with `argv[i]` replaced.
fn with(mut v: Vec<OsString>, i: usize, to: impl Into<OsString>) -> Vec<OsString> {
    v[i] = to.into();
    v
}

// Invocation ---------------------------------------------------------------------------------

#[skuld::test]
fn argv_round_trips_non_utf8_and_leading_dash_args() {
    let a = ShimArgs {
        dir: PathBuf::from(os(b"/tmp/d\xffir")),
        ..args(
            b"/bin/p\xfe",
            &[
                b"\xff\xfe",
                b"-x",
                b"--",
                b"--cosca-elevation-shim=1",
                b"",
                b"a b\n\"'$()",
            ],
        )
    };
    for hex in [false, true] {
        assert_eq!(parsed(&a, hex), a, "hex = {hex}");
    }
}

#[skuld::test]
fn plain_argv_has_the_documented_layout() {
    let id = if cfg!(target_os = "macos") {
        "18446744073709551615:4294967295"
    } else {
        "-"
    };
    let want: Vec<OsString> = [
        EXE,
        "--cosca-elevation-shim=1",
        "/tmp/cosca-x1",
        "4242",
        id,
        "1000",
        "-",
        "--",
        "prog",
        "-a",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    assert_eq!(argv(&args(b"prog", &[b"-a"]), false), want);
}

#[skuld::test]
fn the_identity_form_follows_identity_present() {
    for present in [false, true] {
        let a = ShimArgs {
            cosca_identity: present.then(identity),
            ..args(b"p", &[])
        };
        for hex in [false, true] {
            let v = a.to_argv_for(OsStr::new(EXE), hex, present);
            assert_eq!(
                ShimArgs::parse_for(&v, present).unwrap().unwrap(),
                a,
                "present = {present}"
            );
            assert_eq!(
                ShimArgs::parse_for(&v, !present),
                Err(ShimArgsError::BadIdentity),
                "present = {present}, parsed as the other platform, hex = {hex}"
            );
        }
    }
}

#[skuld::test]
fn identity_syntax() {
    let v = argv(&args(b"p", &[]), false);
    let parse = |t: &str| ShimArgs::parse_for(&with(v.clone(), 4, t), true);
    assert_eq!(
        parse("77:3").unwrap().unwrap().cosca_identity,
        Some(ShimIdentity {
            unique_id: 77,
            id_version: 3
        })
    );
    assert_eq!(
        parse("0:0").unwrap().unwrap().cosca_identity,
        Some(ShimIdentity {
            unique_id: 0,
            id_version: 0
        })
    );
    for bad in [
        "-",
        "",
        "1",
        "1:",
        ":1",
        "1:2:3",
        "a:b",
        "1:4294967296",
        "18446744073709551616:1",
        "+1:2",
        "-1:2",
        " 1:2",
    ] {
        assert_eq!(parse(bad), Err(ShimArgsError::BadIdentity), "{bad:?}");
    }
    assert_eq!(
        ShimArgs::parse_for(&with(v, 4, "-"), false)
            .unwrap()
            .unwrap()
            .cosca_identity,
        None
    );
}

#[skuld::test]
fn hex_form_round_trips_every_byte() {
    let every: Vec<u8> = (1..=255u8).collect();
    let a = args(&every, &[&every, b"--"]);
    let v = argv(&a, true);
    assert_eq!(v[1], "--cosca-elevation-shim=1x");
    assert_eq!(v[7], "--", "the separator stays literal");
    assert!(
        v[2..]
            .iter()
            .filter(|x| *x != "--")
            .all(|x| x.as_encoded_bytes().iter().all(|b| b"0123456789abcdef".contains(b))),
        "every other argument is lowercase hex: {v:?}"
    );
    assert_eq!(v[10], "2d2d", "a program argument `--` is hex, not the separator");
    assert_eq!(parsed(&a, true), a);
}

#[skuld::test]
fn a_program_argument_dashdash_survives_plain_form() {
    let a = args(b"--", &[b"--", b"--"]);
    assert_eq!(parsed(&a, false), a);
}

#[skuld::test]
fn an_empty_program_is_accepted() {
    for hex in [false, true] {
        assert_eq!(parsed(&args(b"", &[b"x"]), hex).program, "", "hex = {hex}");
    }
}

#[skuld::test]
fn the_hex_decoder_accepts_lowercase_only() {
    let v = argv(&args(b"p", &[]), true);
    assert_eq!(v[8], "70");
    for bad in ["7A", "A0", "zz", "abc", "7", " 7", "+7"] {
        assert_eq!(
            ShimArgs::parse(&with(v.clone(), 8, bad)),
            Err(ShimArgsError::BadHex),
            "{bad:?}"
        );
    }
    assert_eq!(ShimArgs::parse(&with(v, 8, "7a")).unwrap().unwrap().program, "z");
}

#[skuld::test]
fn hex_form_structural_errors() {
    let v = argv(&args(b"p", &[b"a"]), true);
    assert_eq!(
        ShimArgs::parse(&with(v.clone(), 7, "2d2d")),
        Err(ShimArgsError::MissingSeparator)
    );
    assert_eq!(
        ShimArgs::parse(&with(v.clone(), 7, "")),
        Err(ShimArgsError::MissingSeparator)
    );
    assert_eq!(
        ShimArgs::parse(&with(v.clone(), 6, to_hex(OsStr::new("X")))),
        Err(ShimArgsError::BadSearch)
    );
    assert_eq!(
        ShimArgs::parse(&with(v.clone(), 3, to_hex(OsStr::new("04242")))),
        Err(ShimArgsError::BadNumber)
    );
    assert_eq!(ShimArgs::parse(&v[..8]), Err(ShimArgsError::TooFewArguments));
    assert_eq!(ShimArgs::parse(&v[..3]), Err(ShimArgsError::TooFewArguments));
}

#[skuld::test]
fn other_versions_are_an_error() {
    for flag in [
        "--cosca-elevation-shim=2",
        "--cosca-elevation-shim=0",
        "--cosca-elevation-shim=1y",
        "--cosca-elevation-shim=",
        "--cosca-elevation-shim",
        "--cosca-elevation-shim=11",
    ] {
        let v = with(argv(&args(b"p", &[]), false), 1, flag);
        assert_eq!(ShimArgs::parse(&v), Err(ShimArgsError::UnknownVersion), "{flag}");
    }
}

#[skuld::test]
fn a_foreign_invocation_is_not_a_shim_invocation() {
    assert_eq!(ShimArgs::parse(&[]), Ok(None));
    assert_eq!(ShimArgs::parse(&[OsString::from(EXE)]), Ok(None));
    assert_eq!(ShimArgs::parse(&[os(EXE.as_bytes()), os(b"--help")]), Ok(None));
    assert_eq!(ShimArgs::parse(&[os(EXE.as_bytes()), os(b"")]), Ok(None));
}

#[skuld::test]
fn structural_errors_name_what_is_wrong() {
    let good = argv(&args(b"p", &[b"a"]), false);
    assert_eq!(ShimArgs::parse(&good[..8]), Err(ShimArgsError::TooFewArguments));
    assert_eq!(ShimArgs::parse(&good[..3]), Err(ShimArgsError::TooFewArguments));
    assert_eq!(
        ShimArgs::parse(&with(good.clone(), 7, "x")),
        Err(ShimArgsError::MissingSeparator)
    );
    for (i, bad) in [(3, "-1"), (3, "+1"), (3, ""), (3, "4294967296"), (5, "x"), (5, "")] {
        assert_eq!(
            ShimArgs::parse(&with(good.clone(), i, bad)),
            Err(ShimArgsError::BadNumber),
            "argv[{i}] = {bad:?}"
        );
    }
    for bad in ["", "p", "X/bin", "--"] {
        assert_eq!(
            ShimArgs::parse(&with(good.clone(), 6, bad)),
            Err(ShimArgsError::BadSearch),
            "{bad:?}"
        );
    }
}

#[skuld::test]
fn dir_must_be_absolute() {
    for hex in [false, true] {
        let v = argv(&args(b"p", &[]), hex);
        for bad in ["", "rel", "./x", "-"] {
            let enc = if hex {
                to_hex(OsStr::new(bad))
            } else {
                OsString::from(bad)
            };
            assert_eq!(
                ShimArgs::parse(&with(v.clone(), 2, enc)),
                Err(ShimArgsError::BadDir),
                "{bad:?}, hex = {hex}"
            );
        }
    }
}

#[skuld::test]
fn leading_zeros_are_rejected() {
    for hex in [false, true] {
        let enc = |t: &str| if hex { to_hex(OsStr::new(t)) } else { OsString::from(t) };
        let v = argv(&args(b"p", &[]), hex);
        for (i, bad) in [(3, "04242"), (3, "00"), (5, "01000")] {
            assert_eq!(
                ShimArgs::parse(&with(v.clone(), i, enc(bad))),
                Err(ShimArgsError::BadNumber),
                "hex = {hex}, argv[{i}]"
            );
        }
        for bad in ["077:03", "077:3", "77:03", "0:00"] {
            assert_eq!(
                ShimArgs::parse_for(&with(v.clone(), 4, enc(bad)), true),
                Err(ShimArgsError::BadIdentity),
                "hex = {hex}, {bad:?}"
            );
        }
        assert_eq!(
            ShimArgs::parse(&with(v, 3, enc("0"))).unwrap().unwrap().cosca_pid,
            0,
            "a lone zero"
        );
    }
}

#[skuld::test]
fn search_path_round_trips_absent_empty_and_present() {
    for (search, token) in [
        (None, OsString::from("-")),
        (Some(OsString::new()), OsString::from("P")),
        (Some(OsString::from("/usr/bin:/bin")), OsString::from("P/usr/bin:/bin")),
        (Some(os(b"/a\xff:-")), os(b"P/a\xff:-")),
    ] {
        let a = ShimArgs {
            search_path: search.clone(),
            ..args(b"p", &[])
        };
        assert_eq!(argv(&a, false)[6], token);
        for hex in [false, true] {
            assert_eq!(parsed(&a, hex).search_path, search, "hex = {hex}");
        }
    }
}

#[skuld::test]
fn a_nul_is_rejected_in_both_forms() {
    // dir, pid, identity, euid, search, program, argument.
    for hex in [false, true] {
        let nul: &[u8] = if hex { b"610062" } else { b"a\0b" };
        for i in [2, 3, 4, 5, 6, 8, 9] {
            let v = with(argv(&args(b"p", &[b"a"]), hex), i, os(nul));
            assert_eq!(
                ShimArgs::parse(&v),
                Err(ShimArgsError::EmbeddedNul),
                "hex = {hex}, argv[{i}]"
            );
        }
    }
}

#[cfg(debug_assertions)]
mod to_argv_asserts {
    use super::*;

    fn nul_in(a: ShimArgs) {
        argv(&a, false);
    }

    #[skuld::test]
    #[should_panic(expected = "execve cannot carry a NUL")]
    fn nul_in_the_program() {
        nul_in(args(b"p\0q", &[]));
    }

    #[skuld::test]
    #[should_panic(expected = "execve cannot carry a NUL")]
    fn nul_in_an_argument() {
        nul_in(args(b"p", &[b"a", b"b\0"]));
    }

    #[skuld::test]
    #[should_panic(expected = "execve cannot carry a NUL")]
    fn nul_in_the_dir() {
        nul_in(ShimArgs {
            dir: PathBuf::from(os(b"/a\0b")),
            ..args(b"p", &[])
        });
    }

    #[skuld::test]
    #[should_panic(expected = "execve cannot carry a NUL")]
    fn nul_in_the_search_path() {
        nul_in(ShimArgs {
            search_path: Some(os(b"/a\0b")),
            ..args(b"p", &[])
        });
    }

    #[skuld::test]
    #[should_panic(expected = "the dir must be absolute")]
    fn a_relative_dir() {
        nul_in(ShimArgs {
            dir: PathBuf::from("rel"),
            ..args(b"p", &[])
        });
    }

    #[skuld::test]
    #[should_panic(expected = "identity is present exactly when identity_present")]
    fn a_missing_identity() {
        let a = ShimArgs {
            cosca_identity: None,
            ..args(b"p", &[])
        };
        a.to_argv_for(OsStr::new(EXE), false, true);
    }

    #[skuld::test]
    #[should_panic(expected = "identity is present exactly when identity_present")]
    fn an_unwanted_identity() {
        let a = ShimArgs {
            cosca_identity: Some(identity()),
            ..args(b"p", &[])
        };
        a.to_argv_for(OsStr::new(EXE), false, false);
    }
}

// Frames -------------------------------------------------------------------------------------

fn all_frames() -> Vec<(Frame, Vec<u8>)> {
    let f = |n| Frame::NotExecuted(n);
    vec![
        (Frame::Hello, b"H".to_vec()),
        (Frame::Status(0x0100), b"S\x00\x01\x00\x00".to_vec()),
        (Frame::Status(-1), b"S\xff\xff\xff\xff".to_vec()),
        (Frame::Status(i32::MIN), b"S\x00\x00\x00\x80".to_vec()),
        (Frame::Status(i32::MAX), b"S\xff\xff\xff\x7f".to_vec()),
        (Frame::Lost(9), b"L\x09\x00\x00\x00".to_vec()),
        (Frame::Lost(i32::MIN), b"L\x00\x00\x00\x80".to_vec()),
        (Frame::Lost(i32::MAX), b"L\xff\xff\xff\x7f".to_vec()),
        (Frame::StatusLost, b"U\x00\x00\x00\x00".to_vec()),
        (f(NotExecuted::ForkFailed(Errno(11))), b"F\x0b\x00\x01\x00".to_vec()),
        (f(NotExecuted::ExecFailed(Errno(2))), b"F\x02\x00\x02\x00".to_vec()),
        (f(NotExecuted::SetupFailed(Errno(24))), b"F\x18\x00\x03\x00".to_vec()),
        (
            f(NotExecuted::TerminatedBeforeExec(Signal(15))),
            b"F\x0f\x00\x04\x00".to_vec(),
        ),
        (f(NotExecuted::ExecFailed(Errno(0xffff))), b"F\xff\xff\x02\x00".to_vec()),
        (Frame::Refused(Refusal::NotCosca), b"R\x7a\x00\x00\x00".to_vec()),
        (Frame::Refused(Refusal::CoscaGone), b"R\x7b\x00\x00\x00".to_vec()),
        (Frame::Refused(Refusal::NoAnswer), b"R\x7c\x00\x00\x00".to_vec()),
        (Frame::Refused(Refusal::Denied), b"R\x7d\x00\x00\x00".to_vec()),
    ]
}

#[skuld::test]
fn frames_round_trip() {
    for (frame, bytes) in all_frames() {
        assert_eq!(frame.encode(), bytes, "{frame:?} encodes");
        assert_eq!(decode_frame(&bytes), Ok(frame), "{bytes:?} decodes");
    }
}

#[skuld::test]
fn every_proper_prefix_of_a_frame_is_truncated() {
    assert_eq!(decode_frame(b""), Err(FrameError::Truncated));
    for (_, bytes) in all_frames() {
        for cut in 1..bytes.len() {
            assert_eq!(
                decode_frame(&bytes[..cut]),
                Err(FrameError::Truncated),
                "{bytes:?}[..{cut}]"
            );
        }
    }
}

#[skuld::test]
fn a_prefix_that_is_already_garbled_is_garbled() {
    for bytes in [
        &b"F\x00\x00"[..],
        b"F\x00\x00\x02",
        b"F\x05\x00\x05",
        b"F\x05\x00\x00",
        b"F\x05\x00\x01\x01",
        b"F\x05\x00\x02\x01",
        b"R\x01",
        b"R\x79",
        b"R\x7e",
        b"R\x7a\x01",
        b"R\x7a\x00\x01",
        b"R\x7a\x00\x00\x01",
        b"U\x01",
        b"U\x00\x00\x01",
        b"U\x00\x00\x00\x01",
    ] {
        assert_eq!(decode_frame(bytes), Err(FrameError::Garbled), "{bytes:?}");
    }
}

#[skuld::test]
fn trailing_bytes_and_unknown_tags_are_garbled() {
    for (_, bytes) in all_frames() {
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            decode_frame(&long),
            Err(FrameError::Garbled),
            "trailing byte after {bytes:?}"
        );
    }
    for tag in [b'A', b'N', b'K', b'T', b'D', b'P', b'h', b's', 0, 0xff] {
        assert_eq!(decode_frame(&[tag, 0, 0, 0, 0]), Err(FrameError::Garbled), "tag {tag}");
        assert_eq!(decode_frame(&[tag]), Err(FrameError::Garbled), "lone tag {tag}");
    }
}

#[skuld::test]
fn f_kinds_round_trip_and_unknown_kind_or_zero_value_is_garbled() {
    let f =
        |value: u16, kind: u16| decode_frame(&[b'F', value as u8, (value >> 8) as u8, kind as u8, (kind >> 8) as u8]);
    assert_eq!(f(5, 1), Ok(Frame::NotExecuted(NotExecuted::ForkFailed(Errno(5)))));
    assert_eq!(f(5, 2), Ok(Frame::NotExecuted(NotExecuted::ExecFailed(Errno(5)))));
    assert_eq!(f(5, 3), Ok(Frame::NotExecuted(NotExecuted::SetupFailed(Errno(5)))));
    assert_eq!(
        f(5, 4),
        Ok(Frame::NotExecuted(NotExecuted::TerminatedBeforeExec(Signal(5))))
    );
    assert_eq!(
        f(0xffff, 4),
        Ok(Frame::NotExecuted(NotExecuted::TerminatedBeforeExec(Signal(0xffff))))
    );
    for kind in [0, 5, 6, 0x100, 0xffff] {
        assert_eq!(f(5, kind), Err(FrameError::Garbled), "kind {kind}");
    }
    for kind in 0..=5 {
        assert_eq!(f(0, kind), Err(FrameError::Garbled), "zero value, kind {kind}");
    }
}

#[skuld::test]
fn r_codes_outside_the_refusal_set_are_garbled() {
    let r = |code: i32| decode_frame(&[&b"R"[..], &code.to_le_bytes()].concat());
    for code in [0, 1, 121, 126, 255, 256, 0x7a00, -1, i32::MIN, i32::MAX] {
        assert_eq!(r(code), Err(FrameError::Garbled), "code {code}");
    }
    assert_eq!(r(122), Ok(Frame::Refused(Refusal::NotCosca)));
}

#[skuld::test]
fn a_nonzero_u_payload_is_garbled() {
    assert_eq!(decode_frame(b"U\x00\x00\x00\x00"), Ok(Frame::StatusLost));
    for payload in [[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [0xff; 4]] {
        assert_eq!(
            decode_frame(&[&b"U"[..], &payload].concat()),
            Err(FrameError::Garbled),
            "{payload:?}"
        );
    }
}

#[cfg(debug_assertions)]
mod encode_asserts {
    use super::*;

    #[skuld::test]
    #[should_panic(expected = "an F value is nonzero and fits 16 bits")]
    fn a_zero_f_value() {
        Frame::NotExecuted(NotExecuted::ExecFailed(Errno(0))).encode();
    }

    #[skuld::test]
    #[should_panic(expected = "an F value is nonzero and fits 16 bits")]
    fn an_f_value_over_16_bits() {
        Frame::NotExecuted(NotExecuted::TerminatedBeforeExec(Signal(0x10000))).encode();
    }

    #[skuld::test]
    #[should_panic(expected = "an F value is nonzero and fits 16 bits")]
    fn a_negative_f_value() {
        Frame::NotExecuted(NotExecuted::ForkFailed(Errno(-1))).encode();
    }
}

// Commands -----------------------------------------------------------------------------------

#[skuld::test]
fn commands_round_trip_on_the_documented_bytes() {
    for (command, byte) in [
        (Command::Allow, b'A'),
        (Command::Deny, b'N'),
        (Command::Kill, b'K'),
        (Command::Terminate, b'T'),
        (Command::Disarm, b'D'),
        (Command::Ping, b'P'),
    ] {
        assert_eq!(command.encode(), byte, "{command:?}");
        assert_eq!(Command::decode(byte), Ok(command), "{byte}");
    }
}

#[skuld::test]
fn every_other_command_byte_is_an_error() {
    for byte in (0..=255u8).filter(|b| !b"ANKTDP".contains(b)) {
        assert_eq!(Command::decode(byte), Err(UnknownCommand(byte)), "{byte}");
    }
}
