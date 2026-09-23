//! Which `lpFile` [`super::plan_runas`] resolves, and when. Every test drives `plan_runas`, never
//! `launch_runas_with_host`, so no consent dialog can appear — see `windows_tests::win_host`.

use super::windows_tests::win_host;
use super::RunasStep;
use crate::command::Command;
use crate::error::Error;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

fn wide_nul(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain([0]).collect()
}

/// A tempdir holding `files`.
fn dir_with(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for f in files {
        std::fs::write(dir.path().join(f), b"x").unwrap();
    }
    dir
}

fn elevated_search(program: &Path) -> Command {
    let mut c = Command::new();
    c.executable(program).args([program]).elevate();
    c
}

/// The located axis prefers the exact name, so choosing first and refusing after would refuse an
/// extensionless `tool` although `tool.exe` sits beside it. Pins that `lp_file_for` resolves
/// through the FILTERED resolver.
#[test]
fn an_extensionless_sibling_does_not_block_the_consent_launch() {
    let dir = dir_with(&["tool", "tool.exe"]);
    let c = elevated_search(&dir.path().join("tool"));
    match super::plan_runas(&c, &win_host(false)) {
        Ok(RunasStep::Launch(launch)) => assert_eq!(launch.file_w, wide_nul(&dir.path().join("tool.exe"))),
        Ok(RunasStep::AlreadyElevated) => panic!("an unelevated host must not short-circuit"),
        Err(e) => panic!("tool.exe exists and must be chosen: {e:?}"),
    }
}

#[test]
fn only_an_extensionless_image_is_not_found_on_the_consent_launch() {
    let dir = dir_with(&["tool"]);
    let c = elevated_search(&dir.path().join("tool"));
    match super::plan_runas(&c, &win_host(false)).map(|_| ()) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

/// The allowlist and completion run AFTER the planner: an already-elevated caller re-spawns
/// through the ordinary backend, which neither searches `PATHEXT` nor uses `lpFile`. Moving
/// `lp_file_for` or `reject_unloadable_image` above `host.plan` turns each of these into an error.
#[test]
fn an_already_elevated_caller_is_not_held_to_the_consent_launch_rules() {
    let extensionless = dir_with(&["tool"]);
    let mut exact = Command::new();
    exact.raw_executable("tool").args(["tool"]).elevate();
    let mut unresolvable = Command::new();
    unresolvable
        .executable("cosca-names-nothing-on-path-7f3a")
        .args(["cosca-names-nothing-on-path-7f3a"])
        .elevate();
    for (what, c) in [
        ("an extensionless raw_executable", exact),
        ("an executable() naming nothing", unresolvable),
        (
            "an executable() naming only an extensionless file",
            elevated_search(&extensionless.path().join("tool")),
        ),
    ] {
        assert!(
            matches!(super::plan_runas(&c, &win_host(true)), Ok(RunasStep::AlreadyElevated)),
            "{what} must short-circuit to AlreadyElevated"
        );
    }
}

/// A relative located name is resolved against `current_dir()`, not this process's cwd. Resolving
/// with no base would read the process cwd, where no `tool.exe` is, and fail with `NotFound`.
#[test]
fn a_relative_name_is_resolved_against_current_dir() {
    let dir = dir_with(&["tool.exe"]);
    let mut c = Command::new();
    c.args([r".\tool.exe"]).current_dir(dir.path()).elevate();
    match super::plan_runas(&c, &win_host(false)) {
        Ok(RunasStep::Launch(launch)) => assert_eq!(
            launch.file_w,
            wide_nul(&dir.path().join(r".\tool.exe")),
            "resolved against current_dir()"
        ),
        Ok(RunasStep::AlreadyElevated) => panic!("an unelevated host must not short-circuit"),
        Err(e) => panic!("tool.exe is in current_dir() and must be found: {e:?}"),
    }
}

const PATH_ONLY_NAME: &str = "cosca-elevate-path-only-3c9d";
const PATH_ONLY_DIR_ENV: &str = "COSCA_FIXTURE_ELEVATE_PATH_ONLY_DIR";

/// A bare name found only on `PATH` resolves there. `.elevate()` refuses env ops and this shared
/// test binary's own environment must not change, so the `PATH` is given to a re-exec of it, which
/// plans the launch in [`fixture_a_name_found_only_on_path`].
#[test]
fn a_name_found_only_on_path_is_resolved_there() {
    let dir = dir_with(&[&format!("{PATH_ONLY_NAME}.exe")]);
    // Control: without that directory on `PATH`, nothing resolves the name.
    match super::plan_runas(&elevated_search(Path::new(PATH_ONLY_NAME)), &win_host(false)).map(|_| ()) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("{PATH_ONLY_NAME} must not resolve from this process's PATH: {other:?}"),
    }
    let mut path = std::ffi::OsString::from(dir.path());
    if let Some(inherited) = std::env::var_os("PATH") {
        path.push(";");
        path.push(inherited);
    }
    crate::test_child::run_fixture_with_env(
        crate::test_child::fixture_path!(fixture_a_name_found_only_on_path),
        &[("PATH", &path), (PATH_ONLY_DIR_ENV, dir.path().as_os_str())],
    );
}

/// Inert in an ordinary suite run, where [`PATH_ONLY_DIR_ENV`] is unset.
#[test]
fn fixture_a_name_found_only_on_path() {
    let Some(dir) = std::env::var_os(PATH_ONLY_DIR_ENV) else {
        return;
    };
    let want = Path::new(&dir).join(format!("{PATH_ONLY_NAME}.exe"));
    match super::plan_runas(&elevated_search(Path::new(PATH_ONLY_NAME)), &win_host(false)) {
        Ok(RunasStep::Launch(launch)) => assert_eq!(launch.file_w, wide_nul(&want)),
        Ok(RunasStep::AlreadyElevated) => panic!("an unelevated host must not short-circuit"),
        Err(e) => panic!("{want:?} is on this process's PATH and must be found: {e:?}"),
    }
}

/// Removes a planted file on drop, so a failing assertion cannot leave it behind.
struct Planted(std::path::PathBuf);

impl Drop for Planted {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.0) {
            log::warn!("could not remove the planted {:?}: {e}", self.0);
        }
    }
}

/// The consent launch does not search the app directory, which a per-user install lets any
/// same-user process write. The name is unique, so no other test resolves the plant.
///
/// Both resolvers are given no `PATH`: cargo puts the test binary's own directory on `PATH` for a
/// Windows test run, and a `PATH` hit is not an app-directory hit.
#[test]
fn the_consent_launch_does_not_search_the_app_directory() {
    let name = format!("cosca-appdir-probe-{}", std::process::id());
    let app_dir = std::env::current_exe().unwrap().parent().unwrap().to_path_buf();
    let planted = Planted(app_dir.join(format!("{name}.exe")));
    std::fs::write(&planted.0, b"x").unwrap();

    // Control: the unelevated resolver does search the app directory, so the plant is findable.
    let found = crate::child::spawn::windows_raw::resolve::resolve_executable(Path::new(&name), None, None)
        .expect("the unelevated resolver searches the app directory");
    assert_eq!(found, planted.0);

    match crate::child::spawn::windows_raw::resolve::resolve_consent_image(Path::new(&name), None, None) {
        Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        other => panic!("the consent launch must not find {name} in the app directory: {other:?}"),
    }
}

/// The consent launch's system directories, in `ShellExecuteEx`'s own order.
#[test]
fn the_consent_launch_searches_system32_then_system_then_windows() {
    let windows = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot is set"));
    let got: Vec<String> = crate::child::spawn::windows_raw::resolve::consent_system_dirs()
        .expect("both directories are known")
        .iter()
        .map(|d| d.to_string_lossy().to_lowercase())
        .collect();
    let want: Vec<String> = [windows.join("System32"), windows.join("System"), windows.clone()]
        .iter()
        .map(|d| d.to_string_lossy().to_lowercase())
        .collect();
    assert_eq!(got, want);
}

/// A directory the query cannot determine fails the bare-name search closed rather than narrowing
/// it to `PATH`, where an entry could outrank System32's copy.
#[test]
fn an_unknown_system_directory_is_an_error_not_a_narrower_search() {
    use crate::child::spawn::windows_raw::resolve::consent_system_dirs_from;
    let denied = || Err(std::io::Error::from_raw_os_error(5));
    let known = || Ok(std::path::PathBuf::from(r"C:\Windows"));
    for (what, got) in [
        ("System32", consent_system_dirs_from(denied(), known())),
        ("the Windows directory", consent_system_dirs_from(known(), denied())),
    ] {
        match got {
            Err(Error::Io(e)) => assert!(e.to_string().contains(what), "{what}: {e}"),
            other => panic!("{what} unknown must be an error, got {other:?}"),
        }
    }
}
