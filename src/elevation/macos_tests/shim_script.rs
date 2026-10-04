//! The AppleScript that elevates the shim instead of the program.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

use super::super::build_shim_script;
use crate::elevation::shim::fixtures::shim_args;
use crate::elevation::shim::protocol::ShimArgs;
use crate::error::{ElevationErrorKind, Error, QuoteErrorKind};

const PREFIX: &str = "do shell script \"";
const SUFFIX: &str = "\" with administrator privileges without altering line endings";

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

/// The shell command inside the script: the literal body with AppleScript's escapes undone, written
/// from the grammar (`\\`, `\"`, `\n`, `\r`, `\t`) and not from the crate's escaper.
fn shell_command(script: &str) -> Vec<u8> {
    let body = script.strip_prefix(PREFIX).unwrap().strip_suffix(SUFFIX).unwrap();
    let mut out = Vec::new();
    let mut bytes = body.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'\\' => out.push(match bytes.next().unwrap() {
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                c @ (b'\\' | b'"') => c,
                c => panic!("undefined escape \\{}", c as char),
            }),
            b'"' => panic!("a raw quote inside the literal"),
            b => out.push(b),
        }
    }
    out
}

fn split(command: &[u8]) -> Vec<Vec<u8>> {
    crate::quote::posix::split(command).unwrap()
}

#[skuld::test]
fn osascript_script_is_ascii_and_uses_the_hex_form() {
    // A program and arguments that no AppleScript literal can carry as bytes: non-UTF-8, and CJK.
    let shim = shim_args("/usr/bin/日本".as_bytes(), &[b"\xff\xfe", "ü\"\\".as_bytes()]);
    let script = build_shim_script(OsStr::new("/opt/host/app"), &shim, None, None)
        .expect("hex keeps a non-UTF-8 program out of the script's bytes");
    assert!(script.is_ascii(), "{script}");
    assert!(script.contains("--cosca-elevation-shim=1x"), "{script}");
    let words = split(&shell_command(&script));
    assert_eq!(words[0], b"exec");
    assert_eq!(words[1], b"/opt/host/app");
    assert_eq!(words[2], b"--cosca-elevation-shim=1x");
    for w in &words[3..] {
        assert!(
            *w == b"--" || w.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{:?}",
            String::from_utf8_lossy(w)
        );
    }
}

#[skuld::test]
fn adversarial_arguments_survive_quoting() {
    // The executable and the directory are the only words that are not hex, so they carry the
    // quoting load: single and double quotes, backslash, space, `$`, backtick, newline, non-ASCII.
    let exe = "/opt/it's \"a\" \\ $HOME `x`\n/ü/app";
    let cwd = "/tmp/it's \"b\" \\ $(id)\n/日本";
    let shim = shim_args(b"/bin/echo", &[b"'; id #", b"\"$(id)\"", b"\n", b"--", b"-n"]);
    let script = build_shim_script(OsStr::new(exe), &shim, Some(Path::new(cwd)), None).unwrap();

    let words = split(&shell_command(&script));
    // `cd -P -- <cwd> && exec <exe> <shim args…>`
    let want_cd: [&[u8]; 5] = [b"cd", b"-P", b"--", cwd.as_bytes(), b"&&"];
    assert_eq!(words[..5], want_cd);
    assert_eq!(words[5], b"exec");
    let tail: Vec<OsString> = words[6..].iter().map(|w| os(w)).collect();
    assert_eq!(tail, shim.to_argv(OsStr::new(exe), true));
    assert_eq!(ShimArgs::parse(&tail).unwrap().unwrap(), shim);
}

#[skuld::test]
fn a_script_over_arg_max_is_command_too_long() {
    let shim = shim_args(b"id", &[]);
    let err = build_shim_script(OsStr::new("/opt/host/app"), &shim, None, Some(10)).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Elevation {
                kind: ElevationErrorKind::CommandTooLong,
                ..
            }
        ),
        "{err:?}"
    );
}

#[skuld::test]
fn a_shim_exe_or_cwd_with_no_text_form_is_a_typed_error() {
    let shim = shim_args(b"id", &[]);
    let cwd = Path::new(OsStr::from_bytes(b"/tmp/\xff"));
    for (exe, cwd) in [(os(b"/opt/\xffapp"), None), (os(b"/opt/app"), Some(cwd))] {
        let err = build_shim_script(&exe, &shim, cwd, None).unwrap_err();
        assert!(
            matches!(&err, Error::Quote(q) if q.kind == QuoteErrorKind::NonUtf8),
            "{err:?}"
        );
    }
}

#[cfg(debug_assertions)]
mod asserts {
    use super::*;

    #[skuld::test]
    #[should_panic(expected = "shim_exe must be POSIX-absolute")]
    fn a_relative_shim_exe_is_a_contract_violation() {
        let _result = build_shim_script(OsStr::new("app"), &shim_args(b"id", &[]), None, None);
    }

    #[skuld::test]
    #[should_panic(expected = "the structural gate must reject a non-absolute cwd")]
    fn a_relative_cwd_is_a_contract_violation() {
        let _result = build_shim_script(
            OsStr::new("/opt/app"),
            &shim_args(b"id", &[]),
            Some(Path::new("rel")),
            None,
        );
    }
}
