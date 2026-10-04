//! The AppleScript that elevates the shim instead of the program.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use super::super::build_shim_script;
use crate::elevation::shim::protocol::{ShimArgs, ShimIdentity};

const PREFIX: &str = "do shell script \"";
const SUFFIX: &str = "\" with administrator privileges without altering line endings";

fn os(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn shim_args(program: &[u8], rest: &[&[u8]]) -> ShimArgs {
    ShimArgs {
        dir: PathBuf::from("/tmp/cosca-x1"),
        cosca_pid: 4242,
        cosca_identity: cfg!(target_os = "macos").then_some(ShimIdentity {
            unique_id: 7,
            id_version: 9,
        }),
        cosca_euid: 1000,
        search_path: None,
        program: os(program),
        args: rest.iter().map(|a| os(a)).collect(),
    }
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

#[skuld::test]
fn osascript_script_is_ascii_and_uses_the_hex_form() {
    // A program and arguments that no AppleScript literal can carry as bytes: non-UTF-8, and CJK.
    let shim = shim_args("/usr/bin/日本".as_bytes(), &[b"\xff\xfe", "ü\"\\".as_bytes()]);
    let script = build_shim_script(OsStr::new("/opt/host/app"), &shim, None, None)
        .expect("hex keeps a non-UTF-8 program out of the script's bytes");
    assert!(script.is_ascii(), "{script}");
    assert!(script.contains("--cosca-elevation-shim=1x"), "{script}");
    let words = cosca_split(&shell_command(&script));
    assert_eq!(words[0], b"exec");
    assert_eq!(words[1], b"/opt/host/app");
    assert_eq!(words[2], b"--cosca-elevation-shim=1x");
    // Every word after the flag except the separator is lowercase hex.
    for w in &words[3..] {
        assert!(
            *w == b"--" || w.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "{:?}",
            String::from_utf8_lossy(w)
        );
    }
}

fn cosca_split(command: &[u8]) -> Vec<Vec<u8>> {
    crate::quote::posix::split(command).unwrap()
}

#[skuld::test]
fn adversarial_arguments_survive_quoting() {
    // The executable and the directory are the only words that are not hex, so they carry the
    // quoting load: single and double quotes, backslash, space, `$`, backtick, newline, non-ASCII.
    let exe = "/opt/it's \"a\" \\ $HOME `x`\n/ü/app";
    let cwd = "/tmp/it's \"b\" \\ $(id)\n/日本";
    let shim = shim_args(b"/bin/echo", &[b"'; id #", b"\"$(id)\"", b"\n", b"--", b"-n"]);
    let script = build_shim_script(OsStr::new(exe), &shim, Some(Path::new(cwd)), None).unwrap();

    let words = cosca_split(&shell_command(&script));
    // `cd -P -- <cwd> && exec <exe> <shim args…>`: the shell reads exactly these words back.
    let want_cd: [&[u8]; 5] = [b"cd", b"-P", b"--", cwd.as_bytes(), b"&&"];
    assert_eq!(words[..5], want_cd);
    assert_eq!(words[5], b"exec");
    let tail: Vec<OsString> = words[6..].iter().map(|w| os(w)).collect();
    assert_eq!(tail, shim.to_argv(OsStr::new(exe), true));
    let parsed = ShimArgs::parse(&tail).unwrap().unwrap();
    assert_eq!(parsed, shim);
}
