use std::os::windows::ffi::OsStrExt;

use windows::Win32::System::Threading::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

use super::{create_process, win32_io_error, RawChild};

fn spawn_long_lived_runas() -> RawChild {
    // A real, NON-elevated child wrapped with the runas flag. `ping -n 5 127.0.0.1` runs
    // ~4s — long-lived enough that kill/teardown must actually terminate it.
    let mut cmdline: Vec<u16> = "ping -n 5 127.0.0.1\0".encode_utf16().collect();
    // A zeroed STARTUPINFOEXW (null lpAttributeList is fine); `create_process` fills cb.
    // `EXTENDED_STARTUPINFO_PRESENT` satisfies create_process's contract (it sizes the
    // struct as extended, so CreateProcessW must be told to treat it as such).
    let mut si = STARTUPINFOEXW::default();
    let (proc, pid) =
        create_process(None, &mut cmdline, &mut si, None, &None, EXTENDED_STARTUPINFO_PRESENT.0).expect("spawn");
    RawChild::new_runas(proc, pid)
}

#[test]
fn runas_kill_of_a_killable_child_returns_and_reaps() {
    let child = spawn_long_lived_runas();
    child
        .kill()
        .expect("kill of our own (non-elevated) runas-flagged child must succeed");
    // kill() returned (no hang). `TerminateProcess` is asynchronous — it initiates termination
    // and returns before the process object signals — so confirm the real exit via a blocking
    // wait on that event (never a racing try_wait poll, never a timer).
    let status = child.wait().expect("wait after kill");
    assert!(!status.success(), "a TerminateProcess(1) exit is non-zero: {status:?}");
}

#[test]
fn runas_teardown_on_drop_returns_promptly() {
    let child = spawn_long_lived_runas();
    child.teardown_on_drop(); // must not hang even though the runas arm is taken
    assert!(
        child.try_wait().expect("try_wait").is_some(),
        "teardown must reap a killable runas child"
    );
}

/// A Win32 failure wrapped as `HRESULT_FROM_WIN32` comes back as its Win32 code, as std's own
/// spawn reports it, so `kind()` classifies it. Any other HRESULT is kept whole.
#[test]
fn win32_io_error_unwraps_a_win32_hresult() {
    use windows::core::{Error, HRESULT};
    let dir = win32_io_error(Error::from_hresult(HRESULT(0x8007_010Bu32 as i32)));
    assert_eq!(dir.raw_os_error(), Some(267));
    assert_eq!(dir.kind(), std::io::ErrorKind::NotADirectory);
    let e_fail = win32_io_error(Error::from_hresult(HRESULT(0x8000_4005u32 as i32)));
    assert_eq!(e_fail.raw_os_error(), Some(0x8000_4005u32 as i32));
}

/// `CreateProcessW` refusing a working directory surfaces `ERROR_DIRECTORY`, not its HRESULT.
#[test]
fn a_refused_cwd_is_reported_as_its_win32_code() {
    let base = tempfile::tempdir().unwrap();
    let missing: Vec<u16> = base
        .path()
        .join("missing")
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let mut cmdline: Vec<u16> = "cmd /c exit 0\0".encode_utf16().collect();
    let mut si = STARTUPINFOEXW::default();
    let err = create_process(
        None,
        &mut cmdline,
        &mut si,
        None,
        &Some(missing),
        EXTENDED_STARTUPINFO_PRESENT.0,
    )
    .expect_err("a missing cwd must be refused");
    let crate::error::Error::Io(err) = err else {
        panic!("expected Error::Io, got {err:?}");
    };
    assert_eq!(err.raw_os_error(), Some(267), "{err:?}");
    assert_eq!(err.kind(), std::io::ErrorKind::NotADirectory, "{err:?}");
}

#[test]
fn terminate_reads_access_denied_as_exit_underway() {
    use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE};
    let denied = windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0));
    assert!(matches!(
        super::classify_terminate(Err(denied)),
        super::Terminated::ExitUnderway
    ));
    let invalid = windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(ERROR_INVALID_HANDLE.0));
    assert!(matches!(
        super::classify_terminate(Err(invalid)),
        super::Terminated::Failed(_)
    ));
    assert!(matches!(super::classify_terminate(Ok(())), super::Terminated::Yes));
}
