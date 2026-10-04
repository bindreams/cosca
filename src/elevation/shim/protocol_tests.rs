use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use super::{decode_frame, Errno, Frame, FrameError, NotExecuted, ShimArgs, ShimArgsError, ShimIdentity, Signal};

const EXE: &str = "/opt/host/app";

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

/// The identity this platform's argv carries: present exactly on macOS.
fn platform_identity() -> Option<ShimIdentity> {
    cfg!(target_os = "macos").then_some(ShimIdentity {
        unique_id: u64::MAX,
        id_version: u32::MAX,
    })
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

fn parsed(a: &ShimArgs, hex: bool) -> ShimArgs {
    ShimArgs::parse(&a.to_argv(OsStr::new(EXE), hex))
        .expect("own argv parses")
        .expect("own argv is a shim invocation")
}

// ShimArgs -----------------------------------------------------------------------------------

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
    let a = args(b"prog", &[b"-a"]);
    let argv: Vec<_> = a.to_argv(OsStr::new(EXE), false);
    let identity = if cfg!(target_os = "macos") {
        "18446744073709551615:4294967295"
    } else {
        "-"
    };
    let want: Vec<OsString> = [
        EXE,
        "--cosca-elevation-shim=1",
        "/tmp/cosca-x1",
        "4242",
        identity,
        "1000",
        "-",
        "--",
        "prog",
        "-a",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    assert_eq!(argv, want);
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn macos_requires_an_identity() {
    let mut argv = args(b"p", &[]).to_argv(OsStr::new(EXE), false);
    argv[4] = OsString::from("-");
    assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::BadIdentity));
    argv[4] = OsString::from("77:3");
    assert_eq!(
        ShimArgs::parse(&argv).unwrap().unwrap().cosca_identity,
        Some(ShimIdentity {
            unique_id: 77,
            id_version: 3
        })
    );
}

#[cfg(not(target_os = "macos"))]
#[skuld::test]
fn linux_forbids_an_identity() {
    let mut argv = args(b"p", &[]).to_argv(OsStr::new(EXE), false);
    argv[4] = OsString::from("77:3");
    assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::BadIdentity));
    argv[4] = OsString::from("-");
    assert_eq!(ShimArgs::parse(&argv).unwrap().unwrap().cosca_identity, None);
}

#[skuld::test]
fn hex_form_round_trips_every_byte() {
    let every: Vec<u8> = (1..=255u8).collect();
    let a = args(&every, &[&every, b"--"]);
    let argv = a.to_argv(OsStr::new(EXE), true);
    assert_eq!(argv[1], "--cosca-elevation-shim=1x");
    assert_eq!(argv[7], "--", "the separator stays literal");
    assert!(
        argv[2..]
            .iter()
            .filter(|x| *x != "--")
            .all(|x| x.as_bytes().iter().all(u8::is_ascii_hexdigit)),
        "every other argument is ASCII hex: {argv:?}"
    );
    assert_eq!(
        argv[8 + 1 + 1],
        "2d2d",
        "a program argument `--` is hex, not the separator"
    );
    assert_eq!(parsed(&a, true), a);
}

#[skuld::test]
fn the_hex_decoder_accepts_lowercase_only() {
    let mut argv = args(b"p", &[]).to_argv(OsStr::new(EXE), true);
    assert_eq!(argv[8], "70");
    argv[8] = OsString::from("7A");
    assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::BadHex), "uppercase");
    argv[8] = OsString::from("7a");
    assert_eq!(ShimArgs::parse(&argv).unwrap().unwrap().program, "z");
}

#[skuld::test]
fn a_nul_is_rejected_in_both_forms() {
    let mut hex = args(b"p", &[b"a"]).to_argv(OsStr::new(EXE), true);
    for i in [2, 8, 9] {
        let saved = std::mem::replace(&mut hex[i], OsString::from("610061"));
        assert_eq!(ShimArgs::parse(&hex), Err(ShimArgsError::EmbeddedNul), "hex argv[{i}]");
        hex[i] = saved;
    }
    let mut plain = args(b"p", &[b"a"]).to_argv(OsStr::new(EXE), false);
    for i in [2, 8, 9] {
        let saved = std::mem::replace(&mut plain[i], os(b"a\0b"));
        assert_eq!(
            ShimArgs::parse(&plain),
            Err(ShimArgsError::EmbeddedNul),
            "plain argv[{i}]"
        );
        plain[i] = saved;
    }
}

#[skuld::test]
fn a_program_argument_dashdash_survives_plain_form() {
    let a = args(b"--", &[b"--", b"--"]);
    assert_eq!(parsed(&a, false), a);
}

#[skuld::test]
fn malformed_hex_is_an_error() {
    let mut argv = args(b"p", &[]).to_argv(OsStr::new(EXE), true);
    argv[8] = OsString::from("zz");
    assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::BadHex));
    argv[8] = OsString::from("abc");
    assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::BadHex), "odd length");
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
        let mut argv = args(b"p", &[]).to_argv(OsStr::new(EXE), false);
        argv[1] = OsString::from(flag);
        assert_eq!(ShimArgs::parse(&argv), Err(ShimArgsError::UnknownVersion), "{flag}");
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
    let good = args(b"p", &[b"a"]).to_argv(OsStr::new(EXE), false);
    // Too short: everything up to the separator, but no program.
    assert_eq!(ShimArgs::parse(&good[..8]), Err(ShimArgsError::TooFewArguments));
    assert_eq!(ShimArgs::parse(&good[..3]), Err(ShimArgsError::TooFewArguments));
    let mut no_sep = good.clone();
    no_sep[7] = OsString::from("x");
    assert_eq!(ShimArgs::parse(&no_sep), Err(ShimArgsError::MissingSeparator));
    for (i, bad) in [(3, "-1"), (3, "+1"), (3, ""), (3, "4294967296"), (5, "x"), (5, "")] {
        let mut v = good.clone();
        v[i] = OsString::from(bad);
        assert_eq!(
            ShimArgs::parse(&v),
            Err(ShimArgsError::BadNumber),
            "argv[{i}] = {bad:?}"
        );
    }
    for bad in ["", "1", "1:", ":1", "1:2:3", "a:b", "1:4294967296", "+1:2"] {
        let mut v = good.clone();
        v[4] = OsString::from(bad);
        assert_eq!(ShimArgs::parse(&v), Err(ShimArgsError::BadIdentity), "{bad:?}");
    }
    for bad in ["", "p", "X/bin", "--"] {
        let mut v = good.clone();
        v[6] = OsString::from(bad);
        assert_eq!(ShimArgs::parse(&v), Err(ShimArgsError::BadSearch), "{bad:?}");
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
        assert_eq!(a.to_argv(OsStr::new(EXE), false)[6], token);
        for hex in [false, true] {
            assert_eq!(parsed(&a, hex).search_path, search, "hex = {hex}");
        }
    }
    let a = ShimArgs {
        search_path: Some(OsString::new()),
        ..args(b"p", &[])
    };
    assert_ne!(
        parsed(&a, false).search_path,
        None,
        "an empty PATH is not an absent one"
    );
}

// Frames -------------------------------------------------------------------------------------

fn all_frames() -> Vec<(Frame, Vec<u8>)> {
    vec![
        (Frame::Hello, b"H".to_vec()),
        (Frame::Status(0x0100), b"S\x00\x01\x00\x00".to_vec()),
        (Frame::Status(-1), b"S\xff\xff\xff\xff".to_vec()),
        (Frame::Lost(9), b"L\x09\x00\x00\x00".to_vec()),
        (Frame::StatusLost, b"U\x00\x00\x00\x00".to_vec()),
        (
            Frame::NotExecuted(NotExecuted::ForkFailed(Errno(11))),
            b"F\x0b\x00\x01\x00".to_vec(),
        ),
        (
            Frame::NotExecuted(NotExecuted::ExecFailed(Errno(2))),
            b"F\x02\x00\x02\x00".to_vec(),
        ),
        (
            Frame::NotExecuted(NotExecuted::SetupFailed(Errno(24))),
            b"F\x18\x00\x03\x00".to_vec(),
        ),
        (
            Frame::NotExecuted(NotExecuted::TerminatedBeforeExec(Signal(15))),
            b"F\x0f\x00\x04\x00".to_vec(),
        ),
        (Frame::Refused(124), b"R\x7c\x00\x00\x00".to_vec()),
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
fn truncated_and_garbled_frames_are_errors() {
    assert_eq!(decode_frame(b""), Err(FrameError::Truncated));
    for (_, bytes) in all_frames().into_iter().filter(|(_, b)| b.len() == 5) {
        for cut in 1..5 {
            assert_eq!(
                decode_frame(&bytes[..cut]),
                Err(FrameError::Truncated),
                "{bytes:?}[..{cut}]"
            );
        }
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            decode_frame(&long),
            Err(FrameError::Garbled),
            "trailing byte after {bytes:?}"
        );
    }
    assert_eq!(decode_frame(b"HH"), Err(FrameError::Garbled), "hello is one byte");
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
