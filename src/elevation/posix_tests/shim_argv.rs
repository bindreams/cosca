//! The front's argv when it elevates the shim instead of the program.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::super::{build_argv, build_shim_argv};
use crate::elevation::shim::fixtures::shim_args;
use crate::elevation::shim::protocol::ShimArgs;
use crate::elevation::{Auth, Backend, Secret};
use crate::error::Error;

const EXE: &str = "/opt/host/app";
const FRONT: &str = "/usr/bin/front";

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn wrapped(backend: Backend, auth: &Auth, shim: &ShimArgs) -> Vec<OsString> {
    wrapped_exe(backend, auth, EXE, shim).unwrap()
}

fn wrapped_exe(backend: Backend, auth: &Auth, exe: impl AsRef<OsStr>, shim: &ShimArgs) -> Result<Vec<OsString>, Error> {
    build_shim_argv(backend, OsStr::new(FRONT), auth, exe.as_ref(), shim, &[])
}

/// Where the shim's own argv starts: at its executable.
fn shim_at(argv: &[OsString], exe: &str) -> usize {
    argv.iter().position(|a| a == exe).unwrap()
}

fn every_auth() -> Vec<Auth> {
    vec![
        Auth::Interactive,
        Auth::NonInteractive,
        Auth::Askpass(PathBuf::from("/usr/bin/askpass")),
        Auth::Stdin(Secret::new("pw")),
        Auth::Gui,
    ]
}

#[skuld::test]
fn sudo_doas_pkexec_argv_wrap_the_program_after_the_shim_separator() {
    let shim = shim_args(b"/usr/bin/id", &[b"-u", b"--", b"-x"]);
    let shim_argv = shim.to_argv(OsStr::new(EXE), false);
    let env = [(OsString::from("FOO"), OsString::from("bar"))];
    for backend in [Backend::Sudo, Backend::Doas, Backend::Pkexec] {
        for auth in every_auth() {
            // doas and pkexec forward no env.
            let env: &[_] = if backend == Backend::Sudo { &env } else { &[] };
            let mut want_front = build_argv(backend, OsStr::new(FRONT), &auth, OsStr::new("PROBE"), &[], env).unwrap();
            assert_eq!(want_front.pop().unwrap(), "PROBE");

            let argv = build_shim_argv(backend, OsStr::new(FRONT), &auth, OsStr::new(EXE), &shim, env).unwrap();
            let at = shim_at(&argv, EXE);
            assert_eq!(argv[..at], want_front[..], "{backend:?} {auth:?}");
            assert_eq!(
                argv[at..],
                shim_argv[..],
                "{backend:?} {auth:?}: the front runs the shim, whole"
            );
            // The program is named only after the shim's own separator.
            let sep = at + shim_argv.iter().position(|a| a == "--").unwrap();
            assert!(!argv[..sep].iter().any(|a| a == "/usr/bin/id"), "{backend:?} {auth:?}");
            assert_eq!(argv[sep + 1], "/usr/bin/id");
        }
    }
}

fn is_hex_form(argv: &[OsString]) -> bool {
    argv[shim_at(argv, EXE) + 1] == "--cosca-elevation-shim=1x"
}

fn parsed_tail(argv: &[OsString]) -> ShimArgs {
    ShimArgs::parse(&argv[shim_at(argv, EXE)..]).unwrap().unwrap()
}

#[skuld::test]
fn pkexec_uses_hex_when_an_argument_is_not_ascii() {
    let multibyte = "日本語".repeat(5);
    let mut cases = vec![
        shim_args(b"/usr/bin/id", &[multibyte.as_bytes()]),
        shim_args(multibyte.as_bytes(), &[]),
        shim_args(b"/usr/bin/id", &[b"\xff\xfe"]),
        shim_args(b"/usr/bin/id", &[b"tab\there"]),
        shim_args(b"/usr/bin/id", &[b"\x7f"]),
        shim_args(b"/usr/bin/id", &[b"a\x1fb"]),
        shim_args(b"/usr/bin/id", &[b"\x1f"]),
    ];
    let mut dir = shim_args(b"/usr/bin/id", &[]);
    dir.dir = PathBuf::from("/tmp/ü");
    cases.push(dir);
    let mut search = shim_args(b"id", &[]);
    search.search_path = Some(os(b"/bin:\xff"));
    cases.push(search);
    for shim in cases {
        let argv = wrapped(Backend::Pkexec, &Auth::NonInteractive, &shim);
        assert!(is_hex_form(&argv), "{shim:?}");
        let at = shim_at(&argv, EXE);
        assert!(
            argv[at + 1..].iter().all(|a| a.as_encoded_bytes().is_ascii()),
            "{shim:?}: ASCII apart from the executable"
        );
        assert_eq!(parsed_tail(&argv), shim);
    }
}

#[skuld::test]
fn pkexec_stays_plain_for_ascii() {
    let mut with_search = shim_args(b"id", &[b"a b", b"'\"$`\\"]);
    with_search.search_path = Some(OsString::from("/usr/bin:/bin"));
    let cases = [
        shim_args(b"/usr/bin/id", &[b"-u", b"--", b"x y"]),
        with_search,
        // The printable range is 0x20..=0x7e, inclusive at both ends.
        shim_args(b"/usr/bin/id", &[b" ", b"~", b"\x20\x7e"]),
        shim_args(b"/usr/bin/id", &[b""]),
        shim_args(b"/usr/bin/id", &[]),
    ];
    for shim in cases {
        let argv = wrapped(Backend::Pkexec, &Auth::NonInteractive, &shim);
        assert!(!is_hex_form(&argv), "{shim:?}");
        assert_eq!(argv[shim_at(&argv, EXE)..], shim.to_argv(OsStr::new(EXE), false)[..]);
        assert_eq!(parsed_tail(&argv), shim);
    }
}

#[skuld::test]
fn sudo_and_doas_stay_plain_for_non_ascii() {
    let shim = shim_args("日本語".as_bytes(), &[b"\xff"]);
    for backend in [Backend::Sudo, Backend::Doas] {
        let argv = wrapped(backend, &Auth::NonInteractive, &shim);
        assert_eq!(
            argv[shim_at(&argv, EXE)..],
            shim.to_argv(OsStr::new(EXE), false)[..],
            "{backend:?}"
        );
    }
}

/// polkit builds the dialog's short command line from the front's argv, starting with the executable.
/// A cut that splits a multi-byte character of the executable leaves invalid UTF-8, and the executable
/// is the one word that hex cannot protect. The rule is exactly: not UTF-8, or a command line over 80
/// bytes whose cut at byte 38 lands inside a character of the executable.
mod pkexec_exe {
    use super::*;

    /// An executable path whose byte 38 is the second byte of a two-byte character, for a total of
    /// `len` bytes. `/` + 36 ASCII bytes + `é` fills bytes 37 and 38.
    fn straddling_exe(len: usize) -> String {
        let mut exe = String::from("/");
        exe.push_str(&"a".repeat(36));
        exe.push('é');
        exe.push_str(&"b".repeat(len - exe.len()));
        assert_eq!(exe.len(), len);
        exe
    }

    fn refused(exe: impl AsRef<OsStr>, shim: &ShimArgs) -> bool {
        match wrapped_exe(Backend::Pkexec, &Auth::NonInteractive, exe, shim) {
            Err(Error::Unsupported { detail, .. }) => {
                assert!(detail.contains("polkit"), "{detail}");
                true
            }
            Ok(_) => false,
            Err(e) => panic!("{e:?}"),
        }
    }

    #[skuld::test]
    fn a_non_utf8_executable_is_refused() {
        let exe = os(b"/opt/\xffapp");
        assert!(refused(&exe, &shim_args(b"id", &[])));
        // sudo and doas have no such limit.
        for backend in [Backend::Sudo, Backend::Doas] {
            wrapped_exe(backend, &Auth::NonInteractive, &exe, &shim_args(b"id", &[])).unwrap();
        }
    }

    #[skuld::test]
    fn a_character_straddling_byte_38_of_a_long_command_line_is_refused() {
        let shim = shim_args(b"id", &[]);
        let exe = straddling_exe(40);
        assert_eq!(exe.as_bytes()[38] & 0xc0, 0x80, "byte 38 is a continuation byte");
        // The shim's own arguments make the line far longer than 80 bytes.
        assert!(refused(&exe, &shim));
    }

    #[skuld::test]
    fn a_utf8_executable_is_accepted_when_the_cut_misses_its_characters() {
        let shim = shim_args(b"id", &[]);
        // Multi-byte, but byte 38 starts a character.
        let aligned = format!("/{}é{}", "a".repeat(37), "b".repeat(5));
        assert_ne!(aligned.as_bytes()[38] & 0xc0, 0x80, "byte 38 starts a character");
        assert!(!refused(&aligned, &shim));
        // A short path made only of multi-byte characters: the whole line is under the cut.
        let mut tiny = shim_args(b"i", &[]);
        tiny.dir = PathBuf::from("/");
        assert!(!refused("/é", &tiny));
        // Multi-byte characters wholly before byte 38.
        assert!(!refused("/日本語/app", &shim));
    }

    #[skuld::test]
    fn the_cut_matters_only_when_the_line_is_over_80_bytes() {
        let exe = straddling_exe(39);
        // The command line is the executable and the shim's arguments, space-separated; the program's
        // length sets it exactly.
        let line_with_program_of = |len: usize| {
            let mut shim = shim_args(&vec![b'p'; len], &[]);
            shim.dir = PathBuf::from("/");
            shim.cosca_pid = 0;
            shim.cosca_euid = 0;
            let argv = shim.to_argv(OsStr::new(&exe), false);
            (shim, argv.iter().map(|a| a.len()).sum::<usize>() + argv.len() - 1)
        };
        let (_, base) = line_with_program_of(0);
        assert!(base <= 80, "the shim's own arguments leave room: {base}");
        let (at_80, line) = line_with_program_of(80 - base);
        assert_eq!(line, 80);
        assert!(!refused(&exe, &at_80), "80 bytes are shown whole");
        let (at_81, line) = line_with_program_of(81 - base);
        assert_eq!(line, 81);
        assert!(refused(&exe, &at_81), "81 bytes are cut at byte 38");
    }
}

#[cfg(debug_assertions)]
mod asserts {
    use super::*;

    #[skuld::test]
    #[should_panic(expected = "shim_exe must be absolute")]
    fn a_relative_shim_exe_is_a_contract_violation() {
        let _result = wrapped_exe(Backend::Sudo, &Auth::NonInteractive, "app", &shim_args(b"id", &[]));
    }
}
