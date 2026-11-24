//! The front's argv when it elevates the shim instead of the program.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::super::{build_argv, build_shim_argv};
use crate::elevation::shim::fixtures::shim_args;
use crate::elevation::shim::protocol::ShimArgs;
use crate::elevation::{Auth, Backend, Secret};
use crate::error::Error;
use crate::role::{ELEVATION_SHIM, HELPER_ENV};

const EXE: &str = "/opt/host/app";
const FRONT: &str = "/usr/bin/front";
/// The word that makes the shim's process the shim, and the program that sets it where the tool takes no
/// assignment: spelled out, not read from the code under test.
const VARIABLE: &str = "__COSCA_HELPER=elevation-shim";
const ENV: &str = "/usr/bin/env";

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

/// The front's own words, then the helper variable in the form the tool delivers or refuses, then the
/// shim's argv whole.
#[skuld::test]
fn the_shim_launch_carries_the_helper_variable_in_the_form_each_tool_delivers() {
    let shim = shim_args(b"/usr/bin/id", &[b"-u"]);
    let tail = shim.to_argv(OsStr::new(EXE), false);
    let words =
        |head: &[&str]| -> Vec<OsString> { head.iter().map(OsString::from).chain(tail.iter().cloned()).collect() };
    // sudo takes the assignment on its own command line, before the `--` that ends its options. Mutants: the
    // assignment after `--` (sudo then looks for a program of that name), an `env` in front of the shim
    // (a rule that names one program no longer matches), no assignment.
    assert_eq!(
        wrapped(Backend::Sudo, &Auth::NonInteractive, &shim),
        words(&[FRONT, "-n", VARIABLE, "--"])
    );
    // doas and pkexec take no assignment: `/usr/bin/env` sets it. Mutants: the assignment before the
    // program (dropped by both tools), a bare `env` (the root's PATH would choose what runs).
    assert_eq!(
        wrapped(Backend::Doas, &Auth::NonInteractive, &shim),
        words(&[FRONT, "-n", "--", ENV, VARIABLE])
    );
    assert_eq!(
        wrapped(Backend::Pkexec, &Auth::NonInteractive, &shim),
        words(&[FRONT, "--disable-internal-agent", "--keep-cwd", ENV, VARIABLE])
    );
    assert_eq!(VARIABLE, format!("{HELPER_ENV}={ELEVATION_SHIM}"));
}

/// `env` takes every word that holds a `=` for an assignment, so it would take a shim executable with one
/// for the assignment and run a later word. Mutant: no check, which starts the wrong program as root.
#[skuld::test]
fn a_shim_executable_with_an_equals_sign_is_refused_where_env_starts_it() {
    let exe = "/opt/a=b/app";
    let shim = shim_args(b"id", &[]);
    for backend in [Backend::Doas, Backend::Pkexec] {
        match wrapped_exe(backend, &Auth::NonInteractive, exe, &shim) {
            Err(Error::Unsupported { detail, .. }) => assert!(detail.contains('='), "{backend:?}: {detail}"),
            other => panic!("{backend:?}: {other:?}"),
        }
    }
    // sudo names the shim after its own `--`: no `env`, no limit.
    let argv = wrapped_exe(Backend::Sudo, &Auth::NonInteractive, exe, &shim).unwrap();
    assert_eq!(argv[shim_at(&argv, exe)], exe);
}

/// Whatever the options, the shim's argv is the same words after the same assignment, and the program is
/// named only after the shim's own separator.
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
            match backend {
                // `[front, options…, --]`: the assignment goes before the `--`.
                Backend::Sudo => want_front.insert(want_front.len() - 1, VARIABLE.into()),
                Backend::Doas | Backend::Pkexec => want_front.extend([ENV.into(), VARIABLE.into()]),
                Backend::Auto => unreachable!(),
            }

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
    ShimArgs::parse(&argv[shim_at(argv, EXE)..]).unwrap()
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

/// polkit builds the dialog's short command line from the front's argv: `/usr/bin/env`, the assignment,
/// then the shim. It cuts a line over 80 bytes at byte 38, which falls inside those ASCII words, so the
/// cut never splits a character of the executable; a non-UTF-8 executable still breaks the line itself.
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

    /// Mutant: the cut is checked against the executable alone, as when the executable began the line.
    #[skuld::test]
    fn a_multibyte_executable_is_accepted_whatever_byte_38_of_it_is() {
        let shim = shim_args(b"id", &[]);
        let exe = straddling_exe(40);
        assert_eq!(
            exe.as_bytes()[38] & 0xc0,
            0x80,
            "byte 38 of the executable is a continuation byte"
        );
        assert!(!refused(&exe, &shim));
        assert!(!refused("/日本語/app", &shim));
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
