//! The front's argv when it elevates the shim instead of the program.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use super::super::build_shim_argv;
use crate::elevation::shim::protocol::{ShimArgs, ShimIdentity};
use crate::elevation::{Auth, Backend};

const EXE: &str = "/opt/host/app";

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
        program: OsString::from_vec(program.to_vec()),
        args: rest.iter().map(|a| OsString::from_vec(a.to_vec())).collect(),
    }
}

fn wrapped(backend: Backend, auth: &Auth, shim: &ShimArgs) -> Vec<OsString> {
    build_shim_argv(backend, OsStr::new("/usr/bin/front"), auth, OsStr::new(EXE), shim, &[]).unwrap()
}

#[skuld::test]
fn sudo_doas_pkexec_argv_wrap_the_program_after_the_shim_separator() {
    let shim = shim_args(b"/usr/bin/id", &[b"-u", b"--", b"-x"]);
    let shim_argv = shim.to_argv(OsStr::new(EXE), false);
    for (backend, front_prefix) in [
        (Backend::Sudo, vec!["/usr/bin/front", "-n", "--"]),
        (Backend::Doas, vec!["/usr/bin/front", "-n", "--"]),
        (
            Backend::Pkexec,
            vec!["/usr/bin/front", "--disable-internal-agent", "--keep-cwd"],
        ),
    ] {
        let argv = wrapped(backend, &Auth::NonInteractive, &shim);
        let prefix: Vec<OsString> = front_prefix.iter().map(OsString::from).collect();
        assert_eq!(argv[..prefix.len()], prefix[..], "{backend:?}");
        let tail = &argv[prefix.len()..];
        assert_eq!(tail, &shim_argv[..], "{backend:?}: the front runs the shim, whole");
        // The program and its args come after the shim's own separator, never before it.
        let at = tail.iter().position(|a| a == "--").unwrap();
        assert_eq!(tail[at + 1], "/usr/bin/id", "{backend:?}");
        assert_eq!(tail[at + 2..], ["-u", "--", "-x"], "{backend:?}");
        assert!(
            !argv[..prefix.len() + at].iter().any(|a| a == "/usr/bin/id"),
            "{backend:?}: the program is named only after the shim separator"
        );
    }
}

const PKEXEC_PREFIX: usize = 3;

/// The shim's argv as the front was given it, parsed back.
fn parsed_tail(argv: &[OsString]) -> ShimArgs {
    ShimArgs::parse(&argv[PKEXEC_PREFIX..]).unwrap().unwrap()
}

fn is_hex_form(argv: &[OsString]) -> bool {
    argv[PKEXEC_PREFIX + 1] == "--cosca-elevation-shim=1x"
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
    ];
    let mut dir = shim_args(b"/usr/bin/id", &[]);
    dir.dir = PathBuf::from("/tmp/ü");
    cases.push(dir);
    let mut search = shim_args(b"id", &[]);
    search.search_path = Some(OsString::from_vec(b"/bin:\xff".to_vec()));
    cases.push(search);
    for shim in cases {
        let argv = wrapped(Backend::Pkexec, &Auth::NonInteractive, &shim);
        assert!(is_hex_form(&argv), "{shim:?}");
        assert!(
            argv[PKEXEC_PREFIX + 2..]
                .iter()
                .all(|a| a.as_encoded_bytes().is_ascii()),
            "{shim:?}: ASCII apart from the executable"
        );
        assert_eq!(parsed_tail(&argv), shim);
    }
}

#[skuld::test]
fn pkexec_stays_plain_for_ascii() {
    let mut with_search = shim_args(b"id", &[b"a b", b"'\"$`\\"]);
    with_search.search_path = Some(OsString::from("/usr/bin:/bin"));
    for shim in [shim_args(b"/usr/bin/id", &[b"-u", b"--", b"x y"]), with_search] {
        let argv = wrapped(Backend::Pkexec, &Auth::NonInteractive, &shim);
        assert!(!is_hex_form(&argv), "{shim:?}");
        assert_eq!(argv[PKEXEC_PREFIX..], shim.to_argv(OsStr::new(EXE), false)[..]);
        assert_eq!(parsed_tail(&argv), shim);
    }
}

#[skuld::test]
fn sudo_and_doas_stay_plain_for_non_ascii() {
    let shim = shim_args("日本語".as_bytes(), &[b"\xff"]);
    for (backend, prefix) in [(Backend::Sudo, 3), (Backend::Doas, 3)] {
        let argv = wrapped(backend, &Auth::NonInteractive, &shim);
        assert_eq!(argv[prefix..], shim.to_argv(OsStr::new(EXE), false)[..], "{backend:?}");
    }
}
