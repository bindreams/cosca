//! Asking the installed `pkexec` its version.

use super::super::{detect_with, probe_pkexec, run_version_probe};
use crate::elevation::pkexec::PkexecVersion;
use crate::elevation::plan::launches_pkexec;
use crate::elevation::plan::{FrontState, Os, Transition};
use crate::elevation::{Auth, Backend, Privilege, Secret};
use crate::error::{ElevationErrorKind, Error};
use std::path::{Path, PathBuf};

/// An executable-mode `#!/bin/sh` script named `pkexec` holding `body`, in `dir`. Never exec'd
/// itself: a test runs it as `/bin/sh <script>` ([`sh`]), which only reads it. A fork elsewhere in
/// this binary can inherit the writer this creates, and exec'ing the file while that child lives
/// fails with `ETXTBSY`; a rename would keep the same inode, so would not help.
fn script(dir: &Path, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("pkexec");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write the script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

/// `/bin/sh <script>`: runs `script` without exec'ing it.
fn sh(script: &Path) -> std::process::Command {
    let mut c = std::process::Command::new("/bin/sh");
    c.arg(script);
    c
}

/// The runner clears the probe's environment: `HOME` is set on the probe's own command before
/// the runner sees it, and the script prints a version only with `HOME` gone.
#[skuld::test]
fn the_probe_runs_in_an_empty_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pkexec = script(
        dir.path(),
        r#"[ "$*" = --version ] && [ -z "${HOME+set}" ] && echo 'pkexec version 121'"#,
    );
    let mut probe = sh(&pkexec);
    probe.arg("--version").env("HOME", "/cosca-probe-home");
    let got = run_version_probe(probe);
    assert!(
        matches!(&got, PkexecVersion::Parsed { version, release: Some(121) } if version == "121"),
        "{got:?}"
    );
}

/// The probe execs the pinned file itself, `/proc/self/fd/N`, with `--version`: the file the
/// launch will exec too, whatever the canonical path names by then.
#[skuld::test]
fn the_probe_execs_the_pinned_file_with_dash_dash_version() {
    use std::os::fd::AsRawFd;
    let file = std::fs::File::open("/dev/null").expect("open");
    let v = probe_pkexec(Path::new("/usr/bin/pkexec"), &file, |probe| {
        assert_eq!(
            probe.get_program(),
            format!("/proc/self/fd/{}", file.as_raw_fd()).as_str()
        );
        assert_eq!(probe.get_args().collect::<Vec<_>>(), ["--version"]);
        PkexecVersion::Unparsed("seen".into())
    });
    assert!(matches!(&v, PkexecVersion::Unparsed(text) if text == "seen"), "{v:?}");
}

/// Only `Backend::Pkexec` with `Auth::Gui`, from a caller not already root, on Linux, launches
/// pkexec: every other request is refused by the planner, runs another backend, or runs none.
#[skuld::test]
fn only_a_linux_gui_pkexec_request_from_a_non_root_caller_launches_pkexec() {
    assert!(launches_pkexec(Os::Linux, Backend::Pkexec, &Auth::Gui, false));
    for backend in [Backend::Auto, Backend::Sudo, Backend::Doas] {
        assert!(!launches_pkexec(Os::Linux, backend, &Auth::Gui, false), "{backend:?}");
    }
    for auth in [
        Auth::Interactive,
        Auth::NonInteractive,
        Auth::Askpass("/usr/bin/ssh-askpass".into()),
        Auth::Stdin(Secret::new("pw")),
    ] {
        assert!(!launches_pkexec(Os::Linux, Backend::Pkexec, &auth, false), "{auth:?}");
    }
    assert!(
        !launches_pkexec(Os::Linux, Backend::Pkexec, &Auth::Gui, true),
        "already root"
    );
    for os in [Os::MacOs, Os::Unix, Os::Windows] {
        assert!(!launches_pkexec(os, Backend::Pkexec, &Auth::Gui, false), "{os:?}");
    }
}

#[skuld::test]
fn a_probe_that_cannot_run_says_so() {
    let v = run_version_probe(std::process::Command::new("/nonexistent/pkexec"));
    assert!(
        matches!(v, PkexecVersion::SpawnFailed(ref e) if e.raw_os_error() == Some(libc::ENOENT)),
        "{v:?}"
    );
}

/// A pkexec that started and ran, but whose wait fails, is `RunFailed`, not `SpawnFailed`: the
/// front is there. With `SIGCHLD` ignored the kernel reaps the child itself and the wait fails with
/// `ECHILD`. (A test is a process of its own under nextest, so the disposition reaches no other.)
///
/// Mutant: a failed wait is `SpawnFailed`.
#[skuld::test]
fn a_probe_whose_wait_fails_after_it_ran_is_run_failed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pkexec = script(dir.path(), "echo 'pkexec version 127'");
    // SAFETY: installing the ignore disposition is async-signal-safe and touches no memory; it is
    // restored below.
    let before = unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
    let v = run_version_probe(sh(&pkexec));
    // SAFETY: restores the disposition read above.
    unsafe { libc::signal(libc::SIGCHLD, before) };
    assert!(
        matches!(v, PkexecVersion::RunFailed(ref e) if e.raw_os_error() == Some(libc::ECHILD)),
        "{v:?}"
    );
}

#[skuld::test]
fn a_probe_that_fails_keeps_its_status_and_output() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pkexec = script(dir.path(), "echo 'pkexec version 127'; echo 'no agent' >&2; exit 3");
    match run_version_probe(sh(&pkexec)) {
        PkexecVersion::Failed { status, stdout, stderr } => {
            assert!(status.contains('3'), "{status}");
            assert_eq!(stdout, "pkexec version 127\n");
            assert_eq!(stderr, "no agent\n");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// A PATH dir holding `pkexec` as a symlink to a real script: `(root, PATH dir, canonical file)`.
fn linked_pkexec() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let (real_dir, bin) = (root.path().join("real"), root.path().join("bin"));
    for d in [&real_dir, &bin] {
        std::fs::create_dir(d).expect("mkdir");
    }
    let real = std::fs::canonicalize(script(&real_dir, "true")).expect("canonicalize");
    std::os::unix::fs::symlink(&real, bin.join("pkexec")).expect("symlink");
    (root, bin, real)
}

/// `detect` pins the canonical file, not the link, and probes that pinned file: the launch then
/// execs the same file through the same descriptor.
#[skuld::test]
fn detect_stores_the_pkexec_it_probed() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let (_root, bin, real) = linked_pkexec();
    let probed = std::cell::RefCell::new(None);
    let host = detect_with(
        Some(bin.as_os_str()),
        Os::Linux,
        false,
        Backend::Pkexec,
        &Auth::Gui,
        |p| std::fs::canonicalize(p),
        |probe| {
            *probed.borrow_mut() = Some(PathBuf::from(probe.get_program()));
            PkexecVersion::Parsed {
                version: "121".into(),
                release: Some(121),
            }
        },
    );
    assert!(matches!(&host.available.pkexec, FrontState::Found(p) if *p == real));
    let pin = host.pkexec_pin.as_ref().expect("pinned");
    assert!(
        pin.as_raw_fd() >= 3,
        "a pin below 3 would be replaced by the child's stdio"
    );
    let (pinned, file) = (pin.metadata().expect("fstat"), std::fs::metadata(&real).expect("stat"));
    assert_eq!(
        (pinned.dev(), pinned.ino()),
        (file.dev(), file.ino()),
        "the pin is the canonical file"
    );
    assert_eq!(
        probed.into_inner(),
        Some(PathBuf::from(format!("/proc/self/fd/{}", pin.as_raw_fd())))
    );
    assert!(
        matches!(&host.pkexec_version, PkexecVersion::Parsed { version, release: Some(121) } if version == "121"),
        "{:?}",
        host.pkexec_version
    );
}

/// A request that does not launch pkexec neither opens nor runs it: the PATH match is stored as
/// found, for the planner's verdict.
#[skuld::test]
fn detect_opens_and_probes_only_for_a_request_that_launches_pkexec() {
    let (_root, bin, _real) = linked_pkexec();
    for (os, backend, auth, elevated) in [
        (Os::MacOs, Backend::Pkexec, Auth::Gui, false),
        (Os::Unix, Backend::Pkexec, Auth::Gui, false),
        (Os::Linux, Backend::Pkexec, Auth::Gui, true),
        (Os::Linux, Backend::Pkexec, Auth::Interactive, false),
        (Os::Linux, Backend::Sudo, Auth::Gui, false),
    ] {
        let host = detect_with(
            Some(bin.as_os_str()),
            os,
            elevated,
            backend,
            &auth,
            |_| panic!("{os:?} {backend:?} {auth:?} {elevated}: canonicalised pkexec"),
            |_| panic!("{os:?} {backend:?} {auth:?} {elevated}: probed pkexec"),
        );
        assert!(
            matches!(host.pkexec_version, PkexecVersion::NotProbed),
            "{:?}",
            host.pkexec_version
        );
        assert!(host.pkexec_pin.is_none());
        assert!(matches!(&host.available.pkexec, FrontState::Found(p) if *p == bin.join("pkexec")));
        assert_eq!(host.os, os);
    }
}

/// The error of a front that could not be examined, as the whole chain prints it.
fn unexamined_chain(state: &FrontState) -> (Option<i32>, String) {
    match state {
        FrontState::Unexamined(error) => (
            crate::error::first_os_code(&**error),
            crate::error::Report(&**error).to_string(),
        ),
        other => panic!("expected Unexamined, got {other:?}"),
    }
}

/// A PATH match whose real file cannot be found is a front that could not be examined: it is
/// neither pinned nor probed, and the error, with the path, is kept for the planner's refusal.
#[skuld::test]
fn a_pkexec_that_cannot_be_canonicalised_is_unexamined_and_not_probed() {
    let (_root, bin, _real) = linked_pkexec();
    let host = detect_with(
        Some(bin.as_os_str()),
        Os::Linux,
        false,
        Backend::Pkexec,
        &Auth::Gui,
        |_| Err(std::io::Error::from_raw_os_error(libc::ELOOP)),
        |_| panic!("probed a pkexec that was never resolved"),
    );
    assert!(host.pkexec_pin.is_none());
    assert!(matches!(host.pkexec_version, PkexecVersion::NotProbed));
    let (code, chain) = unexamined_chain(&host.available.pkexec);
    assert_eq!(code, Some(libc::ELOOP), "{chain}");
    assert!(chain.contains(&bin.join("pkexec").display().to_string()), "{chain}");
    // The planner reports it as a backend that could not be examined, not as one missing.
    match host.plan(Privilege::Elevated, Backend::Pkexec, Auth::Gui) {
        Transition::Reject {
            error:
                Error::Elevation {
                    kind: ElevationErrorKind::BackendUnavailable,
                    detail,
                    source: Some(cause),
                },
        } => {
            assert_eq!(crate::error::first_os_code(&*cause), Some(libc::ELOOP));
            assert!(!detail.contains("not on PATH"), "{detail}");
        }
        other => panic!("expected BackendUnavailable caused by ELOOP, got {other:?}"),
    }
}

/// The pin never follows a symlink: a canonical path that is a link by the time it is opened
/// (here, a canonicalize that returns the link itself) is not pinned, probed or stored.
#[skuld::test]
fn a_canonical_path_that_is_a_symlink_is_not_pinned() {
    let (_root, bin, _real) = linked_pkexec();
    let host = detect_with(
        Some(bin.as_os_str()),
        Os::Linux,
        false,
        Backend::Pkexec,
        &Auth::Gui,
        |p| Ok(p.to_path_buf()),
        |_| panic!("probed a pkexec that was never pinned"),
    );
    assert!(host.pkexec_pin.is_none());
    assert!(matches!(host.pkexec_version, PkexecVersion::NotProbed));
    let (code, chain) = unexamined_chain(&host.available.pkexec);
    assert!(chain.contains(&bin.join("pkexec").display().to_string()), "{chain}");
    // Linux's `O_PATH | O_NOFOLLOW` opens the link itself, which is not a regular file; elsewhere
    // `O_NOFOLLOW` fails the open.
    #[cfg(target_os = "linux")]
    assert!(
        code.is_none() && chain.contains("not a regular file"),
        "{code:?}: {chain}"
    );
    #[cfg(not(target_os = "linux"))]
    assert_eq!(code, Some(libc::ELOOP), "{chain}");
}

/// A FIFO renamed over the canonical path is neither waited on nor pinned: the open does not block
/// and the file is not regular.
#[skuld::test]
fn a_fifo_at_the_canonical_path_is_not_pinned() {
    let (root, bin, _real) = linked_pkexec();
    let fifo = root.path().join("fifo");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("no NUL");
    // SAFETY: a valid NUL-terminated path; the result is checked.
    assert_eq!(
        unsafe { libc::mkfifo(c.as_ptr(), 0o755) },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
    let host = detect_with(
        Some(bin.as_os_str()),
        Os::Linux,
        false,
        Backend::Pkexec,
        &Auth::Gui,
        |_| Ok(fifo.clone()),
        |_| panic!("probed a FIFO"),
    );
    assert!(host.pkexec_pin.is_none());
    let (_, chain) = unexamined_chain(&host.available.pkexec);
    assert!(chain.contains("not a regular file"), "{chain}");
}
