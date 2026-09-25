//! Question 1: does a REAL logon — `CreateProcessWithLogonW`, credentials and all — of a local
//! administrator produce an ELEVATED child? Both probes here create and delete a scratch account
//! and are gated on `COSCA_PROBE_ALLOW_ACCOUNTS`; [`crate::token_filtering`] covers everything that
//! reads token shape without logging anyone on.

use std::os::windows::io::AsRawHandle;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows::Win32::System::Threading::{
    CreateProcessWithLogonW, GetCurrentProcess, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    LOGON_WITH_PROFILE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

use crate::harness::{
    contain, env_block, report_cmdline, require_gate, splice_child_report, wait_for, wide, ScratchAccount,
    CHILD_EXIT_BOUND_MS, WAIT_INCOMPLETE_TOKEN,
};
use crate::windows_probe::mark_test_passed;

/// **Question 1.** Does `CreateProcessWithLogonW`, handed the credentials of a local
/// ADMINISTRATOR, produce an ELEVATED child? `runas.exe` is built on this API and is widely
/// reported not to elevate; this reads the child's own `TokenElevation` / `TokenElevationType` /
/// integrity label rather than relying on that reputation.
///
/// Also measures, in the same call, the two capabilities `ShellExecuteEx` cannot offer: an
/// explicit environment block, and `STARTF_USESTDHANDLES` redirection of the child's stdout.
#[test]
#[ignore = "creates a local user account; opt in with --ignored on a throwaway host"]
fn does_create_process_with_logon_elevate() {
    require_gate(
        "COSCA_PROBE_ALLOW_ACCOUNTS",
        "creates and deletes a local administrator account",
    );
    let mut measured_admin = false;
    let mut measured_std = false;
    for (name, admin) in [("coscaprobeadm", true), ("coscaprobestd", false)] {
        match ScratchAccount::create(name, admin) {
            Ok(account) => {
                if logon_one_account(&account) {
                    if admin {
                        measured_admin = true;
                    } else {
                        measured_std = true;
                    }
                }
            }
            Err(e) => println!("PROBE createprocesswithlogon: could not create {name}: {e}"),
        }
    }
    // Both accounts must be measured, not just either one: the administrator account is the one
    // the whole probe exists to answer (does a real logon reach an elevated token?), and the
    // standard-user account is the contrast that result needs to mean anything at all.
    assert!(
        measured_admin,
        "the Administrators-member scratch account produced no token report, so \
         CreateProcessWithLogonW's elevation result was never actually measured — an account being \
         created is not the same as a report coming back."
    );
    assert!(
        measured_std,
        "the standard-user scratch account produced no token report, so the contrast against the \
         Administrators account — the whole point of running both — was never measured."
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// The body of the probe above, for one account. Split out so the administrator and the standard
/// user are measured by identical code: the ONLY difference between the two runs is the group the
/// account is in, which is exactly the variable UAC token filtering keys on.
///
/// The child runs the FULL chain rather than a bare report. It is the most valuable process in
/// this crate: a real process, from a real logon, owned by a real account of known group
/// membership — the caller cosca's question is actually about. If a freshly logged-on
/// administrator could reach its own elevated token and spawn with it, it would show up here.
///
/// Returns whether the child actually produced a token report — the account being created and
/// `CreateProcessWithLogonW` returning `Ok` are both necessary but not sufficient: the child can
/// still start and exit without ever writing its report. The caller must count only this, not
/// account creation, as "measured".
pub(crate) fn logon_one_account(account: &ScratchAccount) -> bool {
    let role = if account.admin {
        "local ADMINISTRATOR"
    } else {
        "STANDARD user"
    };
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    // The scratch user is not the user who owns this checkout, so it can reach neither the test
    // binary under `target/` nor this process's `%TEMP%`. Give it one directory that holds both
    // the image and its scratch space, and point the child's `%TEMP%` at it. Checked, not
    // discarded: a silent icacls failure here would leave the scratch account unable to read or
    // write anything in `dir`, and every downstream failure (no report, an empty stdout capture)
    // would then be misdiagnosed as an elevation or seclogon result instead of a permissions one.
    let granted = std::process::Command::new("icacls")
        .args([
            dir.path().to_str().unwrap(),
            "/grant",
            &format!("{}:(OI)(CI)F", account.user),
        ])
        .output();
    match &granted {
        Ok(out) if out.status.success() => {}
        Ok(out) => println!(
            "PROBE createprocesswithlogon[{role}]: `icacls {} /grant {}:(OI)(CI)F` FAILED: status={} \
             stdout={} stderr={} — the scratch account may not be able to read or write {}",
            dir.path().display(),
            account.user,
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            dir.path().display()
        ),
        Err(e) => println!(
            "PROBE createprocesswithlogon[{role}]: `icacls` could not be run: {e} — the scratch \
             account may not be able to read or write {}",
            dir.path().display()
        ),
    }
    let exe = dir.path().join("probe.exe");
    std::fs::copy(
        std::env::current_exe().expect("the test binary knows its own path"),
        &exe,
    )
    .expect("copy the probe where the scratch user can execute it");
    let report = dir.path().join("logon.txt");
    let _ = std::fs::remove_file(&report);
    let stdout_file = dir.path().join("stdout.txt");
    let _ = std::fs::remove_file(&stdout_file);

    // An inheritable duplicate of a real file handle: the STARTF_USESTDHANDLES half of the
    // measurement. If seclogon drops it, the file stays empty and that IS the answer.
    let file = std::fs::File::create(&stdout_file).expect("probe stdout file");
    let mut inheritable = HANDLE::default();
    {
        // SAFETY: duplicating a live file handle into this same process, marked inheritable.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(file.as_raw_handle()),
                GetCurrentProcess(),
                &mut inheritable,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .expect("DuplicateHandle for an inheritable stdout");
    }

    // NOT `COSCA_PROBE_CHILD` — see this function's doc comment: the child runs the whole chain.
    let block = env_block(&[
        ("COSCA_PROBE_REPORT_TO", report.display().to_string()),
        ("COSCA_PROBE_ENV_CANARY", "carried-through".into()),
        ("TEMP", dir.path().display().to_string()),
        ("TMP", dir.path().display().to_string()),
    ]);
    let mut cmd = wide(&report_cmdline(&exe));
    let user = wide(&account.user);
    let domain = wide(".");
    let password = wide(&account.password);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: inheritable,
        hStdError: inheritable,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: every wide buffer is NUL-terminated and outlives the call; `block` is NUL-NUL
    // terminated, matching CREATE_UNICODE_ENVIRONMENT. `CREATE_SUSPENDED`: the child must not run
    // before `contain` assigns it to a kill-on-close job.
    let res = unsafe {
        CreateProcessWithLogonW(
            PCWSTR(user.as_ptr()),
            PCWSTR(domain.as_ptr()),
            PCWSTR(password.as_ptr()),
            LOGON_WITH_PROFILE,
            None,
            Some(PWSTR(cmd.as_mut_ptr())),
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            Some(block.as_ptr().cast()),
            None,
            &si,
            &mut pi,
        )
    };
    // SAFETY: our own duplicate, closed once.
    unsafe {
        let _ = CloseHandle(inheritable);
    }

    let mut spliced = String::new();
    match res {
        Err(e) => println!("PROBE createprocesswithlogon[{role}]: FAILED {e:?} — nothing to measure"),
        Ok(()) => {
            let job = contain(&pi, &format!("PROBE createprocesswithlogon[{role}]"));
            // Any `Err` here means this probe's measurement is incomplete; treat the `Result`
            // itself as the check, rather than converting to a string first and pattern-matching
            // English text.
            let exit = match wait_for(&pi, &job, CHILD_EXIT_BOUND_MS) {
                Ok(code) => format!("exit=0x{code:08x}"),
                Err(e) => panic!(
                    "PROBE createprocesswithlogon[{role}]: the logged-on child's exit could not be \
                     confirmed, so this probe's measurement is incomplete and must not be trusted: \
                     {e}. If that error came through kill_and_reap's fallback, only the immediate \
                     child's death is confirmed there — never the rest of the tree — and unwinding \
                     from this panic drops both this probe's temp directory and the caller's scratch \
                     account (its `net user /delete` runs on drop), racing any grandchild that could \
                     still be alive and using either."
                ),
            };
            println!("PROBE createprocesswithlogon[{role}]: STARTED, {exit}. The child reports:");
            splice_child_report(&mut spliced, &report);
            print!("{spliced}");
            // The logged-on child runs the FULL chain (see this function's doc), including its own
            // `spawn_attempts_with` grandchild waits; catch a `WaitFailure` buried in its own report
            // too, before the caller only sees `spliced.contains("token report")` fail with no reason.
            assert!(
                !spliced.contains(WAIT_INCOMPLETE_TOKEN),
                "PROBE createprocesswithlogon[{role}]: the logged-on child's own report shows a \
                 grandchild wait that could not be confirmed, so this probe's measurement is \
                 incomplete and must not be trusted:\n{spliced}"
            );
            let captured = std::fs::read_to_string(&stdout_file).unwrap_or_default();
            println!(
                "PROBE createprocesswithlogon-stdio[{role}]: STARTF_USESTDHANDLES captured {} bytes of child stdout",
                captured.len()
            );
            if captured.is_empty() {
                println!("  => seclogon did NOT carry the caller's stdout handle to the child.");
            } else {
                println!(
                    "  => the caller's stdout handle DID reach the child. First line: {:?}",
                    captured.lines().next()
                );
            }
        }
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
    spliced.contains("token report")
}
