use windows::Win32::System::Threading::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXW};

use super::{create_process, RawChild};

fn spawn_long_lived_runas() -> RawChild {
    // A real, NON-elevated child wrapped with the runas flag. `ping -n 5 127.0.0.1` runs
    // ~4s — long-lived enough that kill/teardown must actually terminate it.
    let mut cmdline: Vec<u16> = "ping -n 5 127.0.0.1\0".encode_utf16().collect();
    // A zeroed STARTUPINFOEXW (null lpAttributeList is fine); `create_process` fills cb.
    // `EXTENDED_STARTUPINFO_PRESENT` satisfies create_process's contract (it sizes the
    // struct as extended, so CreateProcessW must be told to treat it as such).
    let mut si = STARTUPINFOEXW::default();
    let (proc, pid) = create_process(
        None,
        &mut cmdline,
        &mut si,
        &None,
        &None,
        EXTENDED_STARTUPINFO_PRESENT.0,
    )
    .expect("spawn");
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
