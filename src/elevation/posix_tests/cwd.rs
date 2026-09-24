//! Where an elevated POSIX child runs, and the program each backend is handed for it.

use super::super::{rewrite_with_host, rewrite_with_host_and_cwd, PosixRewrite};
use super::rewrite_tests::{derived_argv, elevated_sudo_host, macos_gui_host, sudo_host};
use crate::command::Command;
use crate::elevation::pkexec::PkexecVersion;
use crate::elevation::plan::{BackendSet, Host, Os};
use crate::elevation::{Auth, Backend, ElevatedVia};
use crate::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn exact_tool(cwd: Option<&str>) -> Command {
    let mut c = Command::new();
    c.raw_executable("tool")
        .args(["tool", "-x"])
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
fn every_backend_host() -> Host {
    Host {
        available: BackendSet {
            run0: Some(PathBuf::from("/usr/bin/run0")),
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

/// `raw_executable(path)` with `argv[0] == path`.
fn exact(path: &str) -> Command {
    let mut c = Command::new();
    c.raw_executable(path).args([path]);
    c
}

/// The rewrite, failing the test if it reads this process's cwd.
fn rewrite_reading_nothing(c: &mut Command, host: &Host) -> Result<PosixRewrite, Error> {
    rewrite_with_host_and_cwd(c, host, || {
        panic!("no POSIX backend needs this process's cwd as a path")
    })
}

/// `RunAsIs` spawns the program itself, as an unelevated spawn does.
#[test]
fn an_already_elevated_exact_program_is_spawned_as_an_unelevated_one_is() {
    for cwd in [Some("/work"), Some("sub"), None] {
        let rw = rewrite_reading_nothing(&mut exact_tool(cwd), &elevated_sudo_host()).expect("rewrite");
        let derived = rw.derived.as_ref().expect("derived");
        assert!(
            matches!(derived.executable_spec(), Some(crate::command::ExecutableSpec::Exact(p)) if p == Path::new("tool")),
            "{:?}",
            derived.executable_spec()
        );
        assert_eq!(derived_argv(&rw), [OsString::from("tool"), "-x".into()]);
        assert_eq!(derived.cwd(), cwd.map(Path::new));
    }
}

#[test]
fn an_elevated_exact_program_that_names_no_file_is_refused() {
    for n in ["", ".", "dir/"] {
        let mut c = Command::new();
        c.raw_executable(n)
            .args([n])
            .elevation_backend(Backend::Sudo)
            .elevation_auth(Auth::NonInteractive);
        match rewrite_with_host(&mut c, &sudo_host()) {
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::InvalidInput => {}
            other => panic!(
                "{n:?} names no file and must be Io(InvalidInput), got {:?}",
                other.err()
            ),
        }
    }
}

/// The trampoline takes no directory, so osascript's script `cd`s to an absolute one: its
/// program and directory must come from one reading of the process cwd, or a second reading
/// could load the program from one directory and run it in another.
#[test]
fn the_gui_rewrite_reads_the_process_cwd_exactly_once() {
    let mut gui = exact_tool(None);
    gui.elevation_backend(Backend::Auto).elevation_auth(Auth::Gui);
    let reads = std::cell::Cell::new(0);
    let rw = rewrite_with_host_and_cwd(&mut gui, &macos_gui_host(false), || {
        reads.set(reads.get() + 1);
        Ok(PathBuf::from("/proc-cwd"))
    })
    .expect("rewrite");
    assert_eq!(reads.get(), 1);
    // A build that re-read the real cwd behind the injected one would pass the count alone.
    let derived = rw.derived.as_ref().expect("derived");
    assert_eq!(derived.cwd(), Some(Path::new("/proc-cwd")));
    let argv = derived_argv(&rw);
    assert!(
        argv.iter()
            .any(|a| a.to_string_lossy().contains("cd -P -- /proc-cwd && exec ./tool")),
        "{argv:?}"
    );
}

/// Negative control: a `Search` program's relative `current_dir` is passed through.
#[test]
fn an_elevated_search_programs_relative_cwd_is_passed_through() {
    let mut c = exact_tool(Some("sub"));
    c.executable("tool");
    let rw = rewrite_with_host(&mut c, &sudo_host()).expect("rewrite");
    assert_eq!(rw.derived.as_ref().expect("derived").cwd(), Some(Path::new("sub")));
}

/// osascript needs a path to the cwd; a cwd with none fails loudly, with the OS's kind kept.
#[test]
fn a_gui_exact_program_in_a_cwd_with_no_path_says_why() {
    let mut gui = exact_tool(None);
    gui.elevation_backend(Backend::Auto).elevation_auth(Auth::Gui);
    let r = rewrite_with_host_and_cwd(&mut gui, &macos_gui_host(false), || {
        Err(std::io::Error::from_raw_os_error(libc::EACCES))
    });
    match r {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(e.to_string().contains("working directory as a path"), "{e}");
            let errno = std::error::Error::source(&e)
                .and_then(|s| s.downcast_ref::<std::io::Error>())
                .and_then(std::io::Error::raw_os_error);
            assert_eq!(errno, Some(libc::EACCES), "the errno must survive as the source");
        }
        Err(other) => panic!("expected Io, got {other}"),
        Ok(_) => panic!("a cwd with no path cannot be handed to osascript"),
    }
}

/// Its presence marks a deliberate re-exec of [`fixture_elevated_exact_in_an_unlinked_cwd`].
const FIXTURE_UNLINKED_CWD_ENV: &str = "COSCA_FIXTURE_UNLINKED_CWD";

/// Inert in an ordinary suite run. Re-executed by
/// [`an_elevated_exact_program_in_an_unlinked_cwd_fails_at_the_read`], it waits for one byte on
/// stdin — sent once its cwd has been removed — then rewrites for osascript.
#[test]
fn fixture_elevated_exact_in_an_unlinked_cwd() {
    use std::io::Read;
    if std::env::var_os(FIXTURE_UNLINKED_CWD_ENV).is_none() {
        return;
    }
    std::io::stdin().read_exact(&mut [0u8; 1]).expect("gate byte");
    assert!(std::env::current_dir().is_err(), "precondition: the cwd is unlinked");
    let mut gui = exact_tool(None);
    gui.elevation_backend(Backend::Auto).elevation_auth(Auth::Gui);
    match rewrite_with_host(&mut gui, &macos_gui_host(false)) {
        Err(Error::Io(e)) => {
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}");
            assert!(e.to_string().contains("working directory as a path"), "{e}");
        }
        Err(other) => panic!("expected Io(NotFound), got {other}"),
        Ok(_) => panic!("an unlinked cwd has no path to hand osascript"),
    }
}

/// An unlinked cwd has no path on any OS: the read itself fails, with `NotFound`, where an
/// unsearchable ancestor fails it only on macOS. The cwd is removed from under a child this
/// test spawned in it, so this process's own cwd never moves.
#[test]
fn an_elevated_exact_program_in_an_unlinked_cwd_fails_at_the_read() {
    use std::io::Write;
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("gone");
    std::fs::create_dir(&dir).expect("mkdir");
    let mut child = {
        // Every fork in this binary holds it; see `crate::test_child::run_fixture_with_cwd`.
        let _guard = crate::child::spawn::spawn_lock();
        std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "--test-threads=1",
                "--exact",
                crate::test_child::fixture_path!(fixture_elevated_exact_in_an_unlinked_cwd),
            ])
            .env(FIXTURE_UNLINKED_CWD_ENV, "1")
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the fixture")
    };
    std::fs::remove_dir(&dir).expect("rmdir the fixture's cwd");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"x")
        .expect("release the fixture");
    let out = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// sudo, doas and run0 are started in the caller's directory, as given, handed `./tool`, and run
/// it there (`run0` told `-D .`). None of them needs this process's cwd as a path. pkexec refuses
/// a relative `raw_executable()` ([`pkexec_refuses_a_relative_raw_executable`]).
#[test]
fn a_cwd_keeping_backend_gets_the_program_anchored_to_the_inherited_cwd() {
    for backend in [Backend::Sudo, Backend::Doas, Backend::Run0] {
        for cwd in [None, Some("sub"), Some("/work")] {
            let mut c = under(exact_tool(cwd), backend);
            let rw = rewrite_reading_nothing(&mut c, &every_backend_host()).expect("rewrite");
            let a = derived_argv(&rw);
            assert!(
                a.ends_with(&["./tool".into(), "-x".into()]),
                "{backend:?} {cwd:?}: {a:?}"
            );
            let told: &[&str] = match backend {
                Backend::Run0 => &["-D", "."],
                _ => &[],
            };
            if !told.is_empty() {
                let told: Vec<OsString> = told.iter().map(OsString::from).collect();
                assert!(a.windows(told.len()).any(|w| w == told), "{backend:?}: {a:?}");
            }
            assert_eq!(rw.derived.as_ref().expect("derived").cwd(), cwd.map(Path::new));
        }
    }
}

/// pkexec runs a relative program only if the caller itself can execute it, so a relative
/// `raw_executable()` is refused before anything runs, root or not, and whatever the directory.
#[test]
fn pkexec_refuses_a_relative_raw_executable() {
    for elevated in [false, true] {
        let host = Host {
            elevated,
            ..every_backend_host()
        };
        for path in ["tool", "sub/tool", "../tool", "-x/tool", "./tool"] {
            let mut c = under(exact(path), Backend::Pkexec);
            c.current_dir("/work");
            match rewrite_reading_nothing(&mut c, &host) {
                Err(Error::Unsupported { detail, .. }) => {
                    assert!(detail.contains("absolute"), "{path}: {detail}")
                }
                Err(other) => panic!("{path}: expected Unsupported, got {other}"),
                Ok(rw) => panic!("{path}: accepted as {:?}", derived_argv(&rw)),
            }
        }
    }
}

/// pkexec has no `--`, so a program starting with `-` would be read as an option: it is refused
/// before anything runs, root or not.
#[test]
fn pkexec_refuses_a_leading_dash_program() {
    let commands = || {
        let mut search = Command::new();
        search.executable("-x").args(["-x"]);
        let mut argv_only = Command::new();
        argv_only.args(["-x", "y"]);
        [search, argv_only]
    };
    for elevated in [false, true] {
        let host = Host {
            elevated,
            ..every_backend_host()
        };
        for c in commands() {
            let mut c = under(c, Backend::Pkexec);
            match rewrite_reading_nothing(&mut c, &host) {
                Err(Error::Unsupported { op, .. }) => assert!(op.contains("leading-dash"), "{op}"),
                Err(other) => panic!("expected Unsupported, got {other}"),
                Ok(rw) => panic!("accepted as {:?}", derived_argv(&rw)),
            }
        }
    }
}

/// Every other program reaches pkexec as written: an absolute `raw_executable()`, and a program
/// named by `executable()` or `argv[0]`, relative or bare, which pkexec's own lookup resolves.
#[test]
fn pkexec_gets_every_other_program_as_written() {
    let search = |p: &str| {
        let mut c = Command::new();
        c.executable(p).args([p]);
        c
    };
    let argv_only = |p: &str| {
        let mut c = Command::new();
        c.args([p]);
        c
    };
    for (c, want) in [
        (exact("/opt/tool"), "/opt/tool"),
        (search("bin/tool"), "bin/tool"),
        (search("tool"), "tool"),
        (argv_only("./tool"), "./tool"),
        (argv_only("bin/tool"), "bin/tool"),
    ] {
        let mut c = under(c, Backend::Pkexec);
        let a = derived_argv(&rewrite_reading_nothing(&mut c, &every_backend_host()).expect("rewrite"));
        assert_eq!(a.last(), Some(&OsString::from(want)), "{a:?}");
    }
}

/// The launch execs the very file detection pinned and probed: `/proc/self/fd/N` for the pinned
/// descriptor, with the canonical path as `argv[0]`. The derived command holds the descriptor
/// open until it is spawned.
#[test]
fn pkexec_is_launched_through_the_pinned_descriptor() {
    use std::os::fd::AsRawFd;
    let host = every_backend_host();
    let pin = host.pkexec_pin.clone().expect("pinned");
    let mut c = under(exact("/opt/tool"), Backend::Pkexec);
    let rw = rewrite_reading_nothing(&mut c, &host).expect("rewrite");
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

/// sudo, doas and run0 take a leading-dash program after their `--`, as written.
#[test]
fn a_leading_dash_exact_program_reaches_the_others_as_written() {
    for backend in [Backend::Sudo, Backend::Doas, Backend::Run0] {
        let mut c = Command::new();
        c.raw_executable("-x/tool").args(["-x/tool"]);
        let mut c = under(c, backend);
        let a = derived_argv(&rewrite_reading_nothing(&mut c, &every_backend_host()).expect("rewrite"));
        assert!(a.ends_with(&["--".into(), "-x/tool".into()]), "{backend:?}: {a:?}");
    }
}

/// A pkexec not shown to be polkit 121 or later is refused whatever the command, since every
/// launch passes `--keep-cwd`, which an older pkexec takes for the program.
#[test]
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
        let mut absolute = Command::new();
        absolute.args(["/opt/tool"]);
        let mut in_dir = exact("/opt/tool");
        in_dir.current_dir("/work");
        for mut c in [
            under(absolute, Backend::Pkexec),
            under(exact("/opt/tool"), Backend::Pkexec),
            under(in_dir, Backend::Pkexec),
        ] {
            match rewrite_reading_nothing(&mut c, &host) {
                Err(Error::Unsupported { detail, .. }) => assert!(detail.contains("121"), "{detail}"),
                Err(other) => panic!("{version:?}: expected Unsupported, got {other}"),
                Ok(rw) => panic!("{version:?}: accepted as {:?}", derived_argv(&rw)),
            }
        }
    }
}

/// The refusal is about the pkexec that would run; an already-root caller runs none.
#[test]
fn an_already_root_pkexec_request_runs_whatever_the_version() {
    let host = Host {
        elevated: true,
        pkexec_version: PkexecVersion::NotProbed,
        ..every_backend_host()
    };
    let mut c = under(exact("/opt/tool"), Backend::Pkexec);
    let rw = rewrite_reading_nothing(&mut c, &host).expect("rewrite");
    assert_eq!(rw.report.expect("report").via, ElevatedVia::AlreadyElevated);
}

/// Negative control: a `Search` program still reaches the wrapper as written.
#[test]
fn an_elevated_search_program_is_passed_as_written() {
    let mut c = Command::new();
    c.executable("tool")
        .args(["tool", "-x"])
        .current_dir("/work")
        .elevation_backend(Backend::Sudo)
        .elevation_auth(Auth::NonInteractive);
    let a = derived_argv(&rewrite_with_host(&mut c, &sudo_host()).expect("rewrite"));
    assert_eq!(
        a[a.len() - 3..],
        [OsString::from("--"), "tool".into(), "-x".into()],
        "{a:?}"
    );
}
