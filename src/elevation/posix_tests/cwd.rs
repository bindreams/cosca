//! Where an elevated POSIX child runs, and the program each backend is handed for it.

use super::super::rewrite_with_host;
use super::rewrite_tests::{derived_argv, elevated_sudo_host, sudo_host};
use crate::command::Command;
use crate::elevation::pkexec::PkexecVersion;
use crate::elevation::plan::{BackendSet, Host, Os};
use crate::elevation::{Auth, Backend, ElevatedVia};
use crate::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// `tool -x` under sudo, in `cwd` when given.
fn argv0_tool(cwd: Option<&str>) -> Command {
    let mut c = Command::new();
    c.args(["tool", "-x"])
        .elevation_backend(Backend::Sudo)
        .elevation_auth(Auth::NonInteractive);
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    c
}

/// `c` under `backend`, with the auth that backend accepts.
fn under(mut c: Command, backend: Backend) -> Command {
    let auth = if backend == Backend::Pkexec {
        Auth::Gui
    } else {
        Auth::NonInteractive
    };
    c.elevation_backend(backend).elevation_auth(auth);
    c
}

/// A Linux host offering every CLI backend, for a request that names one; its `pkexec` is polkit
/// 121, pinned by a descriptor detection would have opened (here, on `/dev/null`).
pub(super) fn every_backend_host() -> Host {
    Host {
        available: BackendSet {
            sudo: Some(PathBuf::from("/usr/bin/sudo")),
            doas: Some(PathBuf::from("/usr/bin/doas")),
            pkexec: Some(PathBuf::from("/usr/bin/pkexec")),
            osascript: None,
        },
        pkexec_version: PkexecVersion::Parsed {
            version: "121".into(),
            release: Some(121),
        },
        pkexec_pin: Some(std::sync::Arc::new(
            std::fs::File::open("/dev/null").expect("open /dev/null"),
        )),
        os: Os::Linux,
        ..sudo_host()
    }
}

/// `path` as the whole argv.
fn argv0(path: &str) -> Command {
    let mut c = Command::new();
    c.args([path]);
    c
}

/// `RunAsIs` runs no backend, but the request is still an elevated one: its `raw_executable()`
/// is refused as every backend's is.
#[skuld::test]
fn an_already_elevated_raw_executable_is_refused() {
    for cwd in [Some("/work"), Some("sub"), None] {
        let mut c = argv0_tool(cwd);
        c.raw_executable("tool");
        match rewrite_with_host(&mut c, &elevated_sudo_host()) {
            Err(Error::Unsupported { op, .. }) => assert!(op.ends_with("raw_executable()"), "{cwd:?}: {op}"),
            Err(other) => panic!("{cwd:?}: expected Unsupported, got {other}"),
            Ok(rw) => panic!("{cwd:?}: accepted as {:?}", derived_argv(&rw)),
        }
    }
}

/// Negative control: argv[0]'s relative `current_dir` is passed through.
#[skuld::test]
fn an_elevated_search_programs_relative_cwd_is_passed_through() {
    let mut c = argv0_tool(Some("sub"));
    let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
    assert_eq!(rw.derived.as_ref().expect("derived").cwd(), Some(Path::new("sub")));
}

/// pkexec has no `--`, so a program starting with `-` would be read as an option: it is refused
/// before anything runs, root or not.
#[skuld::test]
fn pkexec_refuses_a_leading_dash_program() {
    for elevated in [false, true] {
        let host = Host {
            elevated,
            ..every_backend_host()
        };
        let mut c = Command::new();
        c.args(["-x", "y"]);
        let mut c = under(c, Backend::Pkexec);
        match rewrite_with_host(&mut c, &host) {
            Err(Error::Unsupported { op, .. }) => assert!(op.contains("leading-dash"), "{op}"),
            Err(other) => panic!("expected Unsupported, got {other}"),
            Ok(rw) => panic!("accepted as {:?}", derived_argv(&rw)),
        }
    }
}

/// Every other program reaches pkexec as written: argv[0], absolute, relative or bare, which
/// pkexec's own lookup resolves.
#[skuld::test]
fn pkexec_gets_every_other_program_as_written() {
    for want in ["/opt/tool", "bin/tool", "tool", "./tool"] {
        let mut c = under(argv0(want), Backend::Pkexec);
        let a = derived_argv(&rewrite_with_host(&mut c, &every_backend_host()).expect("rewrite"));
        assert_eq!(a.last(), Some(&OsString::from(want)), "{a:?}");
    }
}

/// The launch execs the very file detection pinned and probed: `/proc/self/fd/N` for the pinned
/// descriptor, with the canonical path as `argv[0]`. The derived command holds the descriptor
/// open until it is spawned.
#[skuld::test]
fn pkexec_is_launched_through_the_pinned_descriptor() {
    use std::os::fd::AsRawFd;
    let host = every_backend_host();
    let pin = host.pkexec_pin.clone().expect("pinned");
    let mut c = under(argv0("/opt/tool"), Backend::Pkexec);
    let rw = rewrite_with_host(&mut c, &host).expect("rewrite");
    let derived = rw.derived.as_ref().expect("derived");
    assert!(
        derived_argv(&rw).contains(&"--keep-cwd".into()),
        "{:?}",
        derived_argv(&rw)
    );
    assert_eq!(
        derived.executable_path(),
        Some(Path::new(&format!("/proc/self/fd/{}", pin.as_raw_fd())))
    );
    assert_eq!(derived_argv(&rw)[0], OsString::from("/usr/bin/pkexec"));
    // An exec failure is judged on the file exec'd, not on the canonical path.
    assert_eq!(
        rw.backend_path.as_deref(),
        Some(Path::new(&format!("/proc/self/fd/{}", pin.as_raw_fd())))
    );
    drop(host);
    assert!(
        std::sync::Arc::strong_count(&pin) >= 2,
        "the derived command must keep the pinned descriptor open"
    );
}

/// sudo and doas take a leading-dash program after their `--`, as written.
#[skuld::test]
fn a_leading_dash_argv0_program_reaches_the_others_as_written() {
    for backend in [Backend::Sudo, Backend::Doas] {
        let mut c = under(argv0("-x/tool"), backend);
        let a = derived_argv(&rewrite_with_host(&mut c, &every_backend_host()).expect("rewrite"));
        assert!(a.ends_with(&["--".into(), "-x/tool".into()]), "{backend:?}: {a:?}");
    }
}

/// A pkexec not shown to be polkit 121 or later is refused whatever the command, since every
/// launch passes `--keep-cwd`, which an older pkexec takes for the program.
#[skuld::test]
fn a_pkexec_older_than_121_is_refused() {
    for version in [
        PkexecVersion::Parsed {
            version: "0.105".into(),
            release: None,
        },
        PkexecVersion::Parsed {
            version: "120".into(),
            release: Some(120),
        },
        PkexecVersion::Unparsed("polkit 122\n".into()),
        PkexecVersion::SpawnFailed("No such file or directory".into()),
    ] {
        let host = Host {
            pkexec_version: version.clone(),
            ..every_backend_host()
        };
        let mut in_dir = argv0("/opt/tool");
        in_dir.current_dir("/work");
        for mut c in [
            under(argv0("/opt/tool"), Backend::Pkexec),
            under(in_dir, Backend::Pkexec),
        ] {
            match rewrite_with_host(&mut c, &host) {
                Err(Error::Unsupported { detail, .. }) => assert!(detail.contains("121"), "{detail}"),
                Err(other) => panic!("{version:?}: expected Unsupported, got {other}"),
                Ok(rw) => panic!("{version:?}: accepted as {:?}", derived_argv(&rw)),
            }
        }
    }
}

/// The refusal is about the pkexec that would run; an already-root caller runs none.
#[skuld::test]
fn an_already_root_pkexec_request_runs_whatever_the_version() {
    let host = Host {
        elevated: true,
        pkexec_version: PkexecVersion::NotProbed,
        ..every_backend_host()
    };
    let mut c = under(argv0("/opt/tool"), Backend::Pkexec);
    let rw = rewrite_with_host(&mut c, &host).expect("rewrite");
    assert_eq!(rw.report.expect("report").via, ElevatedVia::AlreadyElevated);
}

/// argv[0] reaches the wrapper as written, after its `--`, and the child runs in `current_dir`.
#[skuld::test]
fn an_elevated_argv0_program_is_passed_as_written() {
    let mut c = argv0_tool(Some("/work"));
    let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
    let a = derived_argv(&rw);
    assert_eq!(
        a[a.len() - 3..],
        [OsString::from("--"), "tool".into(), "-x".into()],
        "{a:?}"
    );
    assert_eq!(rw.derived.as_ref().expect("derived").cwd(), Some(Path::new("/work")));
}
