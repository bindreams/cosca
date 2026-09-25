//! Question 2: does UAC token filtering leave an unelevated caller ANY documented way to reach the
//! elevated half of its own split token, or someone else's? Every probe here reads token SHAPE —
//! this process's own, another process's, or a synthesised/derived medium one — without creating an
//! account or logging anyone on; [`crate::logon_routes`] covers the routes that do either of those.

use std::fmt::Write as _;
use std::path::PathBuf;

use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, FILETIME, HANDLE};
use windows::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, DuplicateTokenEx, FreeSid, LogonUserW, SecurityImpersonation,
    SetTokenInformation, TokenIntegrityLevel, TokenPrimary, DISABLE_MAX_PRIVILEGE, LOGON32_LOGON_BATCH,
    LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_LOGON_NETWORK_CLEARTEXT, LOGON32_LOGON_SERVICE,
    LOGON32_PROVIDER_DEFAULT, PSID, SECURITY_MANDATORY_LABEL_AUTHORITY, SECURITY_NT_AUTHORITY, SID_AND_ATTRIBUTES,
    TOKEN_ADJUST_DEFAULT, TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::SystemServices::{
    DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, CreateProcessW, CreateProcessWithTokenW, GetProcessTimes, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, CREATE_NO_WINDOW, CREATE_PROCESS_LOGON_FLAGS, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    STARTUPINFOW,
};

use crate::harness::{
    contain, describe, elevation_type_name, env_block, linked_token, measure, open_own_token, require_gate,
    self_report_cmdline, splice_child_report, token_elevation_type, token_is_elevated, wait_for, wide, wide_path,
    ScratchAccount, Token, CHILD_EXIT_BOUND_MS, WAIT_INCOMPLETE_TOKEN,
};
use crate::windows_probe::mark_test_passed;

/// The body a child runs when a spawning probe re-execs this binary: `COSCA_PROBE_REPORT_TO` names
/// the file to answer through, and `COSCA_PROBE_CHILD` suppresses the nested spawn attempts so a
/// child never recurses. [`crate::logon_routes::logon_one_account`] and [`unelevated_caller_view`]
/// both deliberately spawn their child WITHOUT `COSCA_PROBE_CHILD` set — see each function's doc
/// comment — so that child runs the full chain, the same as [`linked_token_chain_here`] does when
/// run directly.
///
/// A direct, unspawned `--ignored` run (no `COSCA_PROBE_REPORT_TO`) has no report destination to
/// answer through and nothing spawned it, so it is given its own, narrower purpose here rather than
/// duplicating [`linked_token_chain_here`]'s whole-chain probe: report just this process's own
/// token, nothing more.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn measure_this_token() {
    let mut out = String::new();
    // `ShellExecuteEx` cannot carry an environment at all, so whether an explicitly built block
    // survives a token-based spawn is one of the capabilities being measured. The canary is only
    // set by a probe that passed one.
    if let Ok(v) = std::env::var("COSCA_PROBE_ENV_CANARY") {
        let _ = writeln!(out, "  env block: the caller's COSCA_PROBE_ENV_CANARY arrived as {v:?}");
    }
    let report_to = std::env::var_os("COSCA_PROBE_REPORT_TO");
    if report_to.is_some() && std::env::var_os("COSCA_PROBE_CHILD").is_none() {
        // Spawned by `logon_one_account` or `unelevated_caller_view`: the child runs the whole chain.
        measure(&mut out);
    } else {
        // Either a child of `spawn_attempts_with` (`COSCA_PROBE_CHILD` is set, so it does not
        // recurse into more spawn attempts of its own), or a direct, unspawned `--ignored` run
        // with nothing to answer through — both get the same minimal, own-purpose report.
        let _ = writeln!(out, "=== token report (pid {}) ===", std::process::id());
        match open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE) {
            Ok(t) => describe(&mut out, "current process token", t.0),
            Err(e) => {
                let _ = writeln!(out, "  current process token: <{e}>");
            }
        }
        if report_to.is_none() {
            // A direct, unspawned `--ignored` run: nothing else asserts this report says
            // anything, so assert it here — a printed report that never actually describes a
            // token is not a measurement.
            assert!(
                out.contains("integrity="),
                "this process's own token could not be described, so nothing was measured"
            );
        }
    }
    print!("{out}");
    if let Some(dest) = report_to {
        // Spawned by another probe (possibly under a different account): that probe's own
        // marker call already covers it, and this process may not even be able to reach the
        // marker directory — see `env_block`'s doc.
        std::fs::write(&dest, &out)
            .unwrap_or_else(|e| panic!("could not write the report to {}: {e}", PathBuf::from(&dest).display()));
    } else {
        // A direct, unspawned `--ignored` run: nothing else marks this one passed.
        mark_test_passed("COSCA_PROBE_MARKERS");
    }
}

/// Read ANOTHER process's token, named by PID in `COSCA_PROBE_INSPECT_PID`.
///
/// This is the only way to see a genuine UAC-FILTERED administrator token without logging on
/// interactively: point it at the `explorer.exe` of a signed-in split-token administrator and it
/// prints the exact privilege set that survives filtering. Microsoft documents only that "the
/// administrative Windows privileges and SIDs are removed" — no page enumerates which remain — so
/// the list this prints is a measurement filling a documented gap, and it decides whether the
/// `CreateProcessAsUser`/`CreateProcessWithToken` chain is even reachable from a filtered caller.
///
/// Read-only: `PROCESS_QUERY_LIMITED_INFORMATION` plus `TOKEN_QUERY`, nothing else.
#[test]
#[ignore = "platform probe; opt in with --ignored and COSCA_PROBE_INSPECT_PID=<pid>"]
fn measure_another_process_token() {
    // Whether this run resolved `pid` itself (looking specifically for `explorer.exe`) or took it
    // on trust from the caller — see the image-identity check below for why that distinction
    // matters.
    let (pid, expect_explorer): (u32, bool) = match std::env::var("COSCA_PROBE_INSPECT_PID") {
        Ok(v) => (
            v.trim().parse().expect("COSCA_PROBE_INSPECT_PID must be a decimal PID"),
            false,
        ),
        // With no target named, go looking for the interesting one: the shell of a signed-in
        // user. `tasklist` is read-only.
        Err(_) => {
            let out = std::process::Command::new("tasklist")
                .args(["/fi", "IMAGENAME eq explorer.exe", "/fo", "csv", "/nh"])
                .output()
                .expect("tasklist must be runnable to find a target process");
            let pid = String::from_utf8_lossy(&out.stdout)
                .lines()
                .find_map(|l| l.split(',').nth(1)?.trim_matches('"').parse().ok())
                .expect(
                    "no explorer.exe is running, so this host has no signed-in desktop whose \
                     filtered token could be read. Point the probe at a specific process with \
                     COSCA_PROBE_INSPECT_PID=<pid>, or run it on a machine with an interactive \
                     session — a headless CI runner cannot take this measurement.",
                );
            (pid, true)
        }
    };

    // SAFETY: a query-only open of a live PID; the handle is closed exactly once below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .unwrap_or_else(|e| panic!("could not open pid {pid} for query: {e}"));

    // Verify what this handle actually IS, on the handle itself, before trusting its token: a PID
    // is a number the OS can reuse for an unrelated process the moment the original one exits —
    // between the `tasklist` snapshot above (or whatever supplied `COSCA_PROBE_INSPECT_PID`) and
    // this `OpenProcess` call, `pid` could already name a different process. `GetProcessTimes`'s
    // creation time is reported alongside the image for the same reason: it is evidence a reader
    // can use to judge how likely that reuse race was, even though this probe has no earlier
    // creation time of its own to compare it against.
    let mut image_w = [0u16; 1024];
    let mut image_len = image_w.len() as u32;
    // SAFETY: `handle` is live; `image_w` outlives the call and `image_len` names its capacity.
    let image_result =
        unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(image_w.as_mut_ptr()), &mut image_len) };
    let image_path = image_result.map(|()| String::from_utf16_lossy(&image_w[..image_len as usize]));

    let mut creation = FILETIME::default();
    let (mut exit_time, mut kernel_time, mut user_time) =
        (FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: `handle` is live; every out-param below is a plain stack value borrowed for the call.
    let times_result =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit_time, &mut kernel_time, &mut user_time) };

    let mut token = HANDLE::default();
    // SAFETY: `handle` is live; the token is wrapped in a guard immediately.
    let opened = unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token) };
    // SAFETY: our own process handle, closed once.
    unsafe {
        let _ = CloseHandle(handle);
    }

    let image_path = image_path.unwrap_or_else(|e| {
        panic!("could not confirm pid {pid}'s image via QueryFullProcessImageNameW before trusting its token: {e}")
    });
    opened.unwrap_or_else(|e| panic!("could not open pid {pid}'s token: {e}"));
    let token = Token(token);

    let mut out = String::new();
    let _ = writeln!(out, "=== token of pid {pid} (image={image_path}) ===");
    match times_result {
        Ok(()) => {
            let _ = writeln!(
                out,
                "  process creation time (FILETIME): high={} low={}",
                creation.dwHighDateTime, creation.dwLowDateTime
            );
        }
        Err(e) => {
            let _ = writeln!(out, "  GetProcessTimes: <{e}>");
        }
    }
    if expect_explorer {
        assert!(
            image_path.to_lowercase().ends_with("explorer.exe"),
            "pid {pid} was found via tasklist as explorer.exe, but the handle this probe opened \
             reports its image as {image_path} instead — the PID was almost certainly reused by \
             an unrelated process between the tasklist snapshot and OpenProcess, so the token \
             below is NOT explorer.exe's and this measurement must not be trusted"
        );
    }
    describe(&mut out, "that process's token", token.0);
    match linked_token(token.0) {
        Ok(linked) => describe(&mut out, "its TokenLinkedToken", linked.0),
        Err(e) => {
            let _ = writeln!(out, "  its TokenLinkedToken: <{e}>");
        }
    }
    print!("{out}");
    assert!(
        out.contains("integrity="),
        "the target process's token could not be described, so nothing was measured"
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// The UAC policy in force. Without these values a token-shape measurement is uninterpretable: on
/// a machine with `EnableLUA=0` there is no filtering to observe and every result below would be
/// a misleading "elevation just works".
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn measure_uac_policy() {
    const KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let mut any = false;
    for name in [
        "EnableLUA",
        "ConsentPromptBehaviorAdmin",
        "ConsentPromptBehaviorUser",
        "FilterAdministratorToken",
        "LocalAccountTokenFilterPolicy",
        "EnableInstallerDetection",
        "PromptOnSecureDesktop",
    ] {
        // `reg query` is read-only; nothing here writes to the registry.
        let out = std::process::Command::new("reg")
            .args(["query", KEY, "/v", name])
            .output();
        match out {
            Ok(o) if o.status.success() => {
                any = true;
                let text = String::from_utf8_lossy(&o.stdout);
                let value = text
                    .lines()
                    .find(|l| l.contains(name))
                    .map_or("<unparsed>", str::trim)
                    .to_string();
                println!("PROBE uac-policy: {value}");
            }
            Ok(_) => println!("PROBE uac-policy: {name} = <not set>"),
            Err(e) => println!("PROBE uac-policy: {name} = <reg query failed: {e}>"),
        }
    }
    assert!(
        any,
        "not one UAC policy value could be read, so no token result below is interpretable"
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// Question 2, measured at whatever integrity this process runs at. Read together with
/// [`unelevated_caller_view`], which takes the same measurement at medium integrity and is the one
/// that can actually answer the question — but only when its own report confirms
/// `TokenIsElevated=false`; see that function's doc for when it cannot.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn linked_token_chain_here() {
    let mut out = String::new();
    measure(&mut out);
    print!("{out}");
    // A spawned grandchild that never exited is not an ordinary measurement outcome: `wait_for`
    // kills and recovers it, but nothing downstream distinguishes that from a normal negative
    // result. Fail loudly and specifically here instead of letting a hang masquerade as "step 1"
    // simply lacking a recognised outcome line below.
    assert!(
        !out.contains(WAIT_INCOMPLETE_TOKEN),
        "a spawned child's exit could not be confirmed, so this probe's measurement is incomplete \
         and must not be trusted:\n{out}"
    );
    // `out.contains("step 1")` alone can never fail: `measure` always emits a "step 1 ..." line,
    // whether it succeeded or not, so that check asserts nothing. Require the line to actually
    // show a result — a successful open, or a failure carrying a real (non-empty) error — so a
    // future report-format change that dropped the outcome would fail this loudly instead of
    // sailing through a vacuous substring match.
    assert!(
        out.contains("step 1 GetTokenInformation(TokenLinkedToken): OK")
            || out.contains("step 1 OpenProcessToken: FAILED <")
            || out.contains("step 1 GetTokenInformation(TokenLinkedToken): FAILED <"),
        "the chain's step 1 produced neither a success nor a real error code, so nothing was \
         measured:\n{out}"
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// **Question 2, properly.** Derive a medium-integrity token, start this binary under it, and read
/// its report. Where this process is the FULL half of a UAC split, the medium token is its own
/// `TokenLinkedToken` — the genuine filtered token Windows made, not an imitation. Otherwise one
/// is synthesised by disabling the Administrators SID and stamping the medium integrity label,
/// which is close but NOT identical, and the report says which was used.
#[test]
#[ignore = "platform probe; opt in with --ignored"]
fn unelevated_caller_view() {
    let own = open_own_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT)
        .expect("the probe needs its own token to derive a medium one");

    let etype = token_elevation_type(own.0)
        .unwrap_or_else(|e| panic!("could not read this process's own TokenElevationType: {e}"));
    println!(
        "PROBE unelevated-view: this process is elevation_type={etype} {}",
        elevation_type_name(etype)
    );

    let (medium, provenance) = if etype == 2 {
        match linked_token(own.0) {
            Ok(linked) => {
                let mut primary = HANDLE::default();
                // SAFETY: `linked` is live; the duplicate is wrapped in a `Token` immediately.
                unsafe {
                    DuplicateTokenEx(
                        linked.0,
                        TOKEN_ALL_ACCESS,
                        None,
                        SecurityImpersonation,
                        TokenPrimary,
                        &mut primary,
                    )
                }
                .expect("DuplicateTokenEx on the linked filtered token");
                (Token(primary), "the genuine UAC-filtered linked token")
            }
            Err(e) => panic!("this process is the full half of a split but its linked token is unreadable: {e}"),
        }
    } else {
        (
            synthesise_medium_token(&own),
            "a SYNTHESISED medium token (no UAC split on this account)",
        )
    };
    println!("PROBE unelevated-view: medium token provenance = {provenance}");

    let mut report = String::new();
    describe(&mut report, "medium token about to be used", medium.0);
    print!("{report}");

    // `describe` above already prints this token's `elevated=` flag buried among privileges;
    // surface it again on its own, because it is the one bit that decides whether what follows is
    // actually a measurement of an unelevated caller. Measured on a GitHub runner: a Default,
    // non-split admin token (`elevation_type=1`) has synthesis disable the Administrators SID and
    // lower integrity to Medium, but `TokenIsElevated` is fixed at token creation from the source
    // logon's elevation type and neither of those adjustments touches it — so the synthesised
    // token still reads `elevated=true`. Only the genuine `TokenLinkedToken` route (`etype == 2`, a
    // real UAC split) clears it. Print this prominently instead of asserting it false: on a
    // non-split admin account it is EXPECTED to stay true, so asserting false would fail this
    // probe on exactly the hosts it is meant to run on.
    let medium_is_elevated = token_is_elevated(medium.0)
        .unwrap_or_else(|e| panic!("could not read the medium token's own TokenIsElevated flag: {e}"));
    if medium_is_elevated {
        println!(
            "PROBE unelevated-view: medium token TokenIsElevated=true -- NOT a genuine unelevated \
             view. Integrity was lowered and the Administrators SID disabled, but this token was \
             derived from a non-split admin token, and TokenIsElevated cannot be cleared that way. \
             Read everything below as \"lowered integrity, still an elevated token\", not as an \
             unelevated caller's report."
        );
    } else {
        println!("PROBE unelevated-view: medium token TokenIsElevated=false -- a genuine unelevated view.");
    }

    let dir = tempfile::tempdir().expect("probe needs a temp dir");

    // Two routes, because `CreateProcessAsUserW` hands the child the caller's window station and
    // desktop unchanged, and a lowered-integrity token cannot always open them, which can make the
    // child die in loader init (STATUS_DLL_INIT_FAILED, 0xC0000142) before it can report anything
    // — measured on a desktop over SSH. On a GitHub runner this route instead SUCCEEDED and
    // produced a full report, so 0xC0000142 is a possible failure mode of this route, not its
    // guaranteed outcome. `CreateProcessWithTokenW` goes through the Secondary Logon service,
    // which sets the station and desktop up itself. Either one that yields a report answers the
    // question; both are tried so a station ACL cannot be mistaken for "elevation is impossible".
    let mut spliced = String::new();
    for (route, use_seclogon) in [("CreateProcessAsUserW", false), ("CreateProcessWithTokenW", true)] {
        let child_report = dir.path().join(format!("{route}.txt"));
        let _ = std::fs::remove_file(&child_report);
        let block = env_block(&[("COSCA_PROBE_REPORT_TO", child_report.display().to_string())]);
        let mut cmd = wide(&self_report_cmdline());
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: `cmd` and `block` are correctly terminated and outlive the call. `CREATE_SUSPENDED`:
        // the child must not run before `contain` assigns it to a kill-on-close job.
        let started = unsafe {
            if use_seclogon {
                CreateProcessWithTokenW(
                    medium.0,
                    CREATE_PROCESS_LOGON_FLAGS(0),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            } else {
                CreateProcessAsUserW(
                    Some(medium.0),
                    None,
                    Some(PWSTR(cmd.as_mut_ptr())),
                    None,
                    None,
                    false,
                    CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    Some(block.as_ptr().cast()),
                    None,
                    &si,
                    &mut pi,
                )
            }
        };
        match started {
            Err(e) => println!("PROBE unelevated-view: {route} with the medium token FAILED {e:?}"),
            Ok(()) => {
                let job = contain(&pi, &format!("PROBE unelevated-view[{route}]"));
                // Any `Err` here — not just one whose message happens to say "did not exit within"
                // — means this route's measurement is incomplete; treat the `Result` itself as the
                // check, rather than converting to a string first and pattern-matching English text.
                let exit = match wait_for(&pi, &job, CHILD_EXIT_BOUND_MS) {
                    Ok(code) => format!("exit=0x{code:08x}"),
                    Err(e) => panic!(
                        "PROBE unelevated-view: {route}'s medium child's exit could not be \
                         confirmed, so this route's measurement is incomplete and must not be \
                         trusted: {e}"
                    ),
                };
                println!("PROBE unelevated-view: {route} started a medium child, {exit}. It reports:");
                splice_child_report(&mut spliced, &child_report);
                print!("{spliced}");
                // The medium child runs the FULL chain (`measure`, the same as
                // `linked_token_chain_here` runs directly), which itself spawns grandchildren
                // through `spawn_attempts_with` — so a `WaitFailure` any of THOSE hit lands in the
                // child's own report text, spliced in above. Catch that the same way as the medium
                // child's own direct wait failure, before the loop clears `spliced` for the next
                // route and discards the evidence.
                assert!(
                    !spliced.contains(WAIT_INCOMPLETE_TOKEN),
                    "PROBE unelevated-view: {route}'s medium child's own report shows a grandchild \
                     wait that could not be confirmed, so this route's measurement is incomplete \
                     and must not be trusted:\n{spliced}"
                );
            }
        }
        if spliced.contains("token report") {
            break;
        }
        spliced.clear();
    }
    // `dir` is a `tempfile::TempDir`; it removes itself on drop.
    assert!(
        spliced.contains("token report"),
        "no medium-integrity child produced a report, so the unelevated caller's view was NOT \
         measured. Every other result in this file was taken at this process's own integrity level \
         and must not be read as an unelevated result."
    );
    if medium_is_elevated {
        println!(
            "PROBE unelevated-view: measured, but LABEL AS ELEVATED: the medium token's \
             TokenIsElevated stayed true (see above), so this is a lowered-integrity elevated \
             caller's view, not an unelevated one."
        );
    } else {
        println!("PROBE unelevated-view: measured, and correctly labelled as an unelevated caller's view.");
    }
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// A medium-integrity token for an account that has no UAC split to borrow one from: disable the
/// Administrators SID (what filtering does to the groups) and stamp the medium integrity label
/// (what filtering does to the label). It is NOT a real filtered token — notably the privilege set
/// is whatever `DISABLE_MAX_PRIVILEGE` leaves — so any result taken under it is weaker evidence,
/// and the caller says so.
fn synthesise_medium_token(own: &Token) -> Token {
    let mut admins = PSID::default();
    // SAFETY: the standard S-1-5-32-544 construction; freed below.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_NT_AUTHORITY,
            2,
            SECURITY_BUILTIN_DOMAIN_RID as u32,
            DOMAIN_ALIAS_RID_ADMINS as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut admins,
        )
    }
    .expect("AllocateAndInitializeSid(BUILTIN\\Administrators)");
    let disable = [SID_AND_ATTRIBUTES {
        Sid: admins,
        Attributes: 0,
    }];
    let mut restricted = HANDLE::default();
    // SAFETY: `own` is live and `disable` outlives the call.
    let made = unsafe {
        CreateRestrictedToken(
            own.0,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &mut restricted,
        )
    };
    // SAFETY: `admins` came from AllocateAndInitializeSid and is freed exactly once.
    unsafe {
        FreeSid(admins);
    }
    made.expect("CreateRestrictedToken");
    let restricted = Token(restricted);

    let mut medium = PSID::default();
    // SAFETY: the standard S-1-16-8192 construction; freed below.
    unsafe {
        AllocateAndInitializeSid(
            &SECURITY_MANDATORY_LABEL_AUTHORITY,
            1,
            SECURITY_MANDATORY_MEDIUM_RID as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &mut medium,
        )
    }
    .expect("AllocateAndInitializeSid(Medium Mandatory Level)");
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium,
            Attributes: 0x20, // SE_GROUP_INTEGRITY
        },
    };
    // SAFETY: `label` matches TokenIntegrityLevel and `medium` is alive for the call.
    let set = unsafe {
        SetTokenInformation(
            restricted.0,
            TokenIntegrityLevel,
            std::ptr::addr_of!(label).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    };
    // SAFETY: `medium` came from AllocateAndInitializeSid and is freed exactly once.
    unsafe {
        FreeSid(medium);
    }
    set.expect("SetTokenInformation(TokenIntegrityLevel = Medium)");
    restricted
}

/// Does `CreateProcessW`'s `lpApplicationName` really behave as documented — "The function does not
/// use the search path. This parameter must include the file name extension; no default extension
/// is assumed"? `windows_shell_resolution.rs` measured `ShellExecuteEx` violating the intuitive
/// reading of ITS docs twice, so this claim is measured rather than trusted. It is the whole
/// reason a `CreateProcess*` route would be an improvement.
#[test]
#[ignore = "plants a batch file next to the target; opt in with --ignored"]
fn does_createprocessw_lpapplicationname_apply_pathext() {
    let dir = tempfile::tempdir().expect("probe needs a temp dir");
    let marker = dir.path().join("bat-marker.txt");
    std::fs::write(
        dir.path().join("tool.bat"),
        format!("@echo off\r\necho ran > \"{}\"\r\n", marker.display()),
    )
    .expect("plant tool.bat");

    // Absolute, extensionless, NONEXISTENT — the shape `raw_executable("tool")` produces.
    let missing = dir.path().join("tool");
    let app = wide_path(&missing);
    let si = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    // SAFETY: `app` is NUL-terminated and outlives the call; no command line is supplied, which is
    // legal when lpApplicationName is present. `CREATE_SUSPENDED`: the child must not run before
    // `contain` assigns it to a kill-on-close job.
    let res = unsafe {
        CreateProcessW(
            PCWSTR(app.as_ptr()),
            None,
            None,
            None,
            false,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    let started = res.is_ok();
    if started {
        let job = contain(&pi, "PROBE createprocessw-pathext");
        wait_for(&pi, &job, CHILD_EXIT_BOUND_MS)
            .unwrap_or_else(|e| panic!("PROBE createprocessw-pathext: child did not exit cleanly: {e}"));
    }
    let bat_ran = marker.exists();
    println!(
        "PROBE createprocessw-pathext: started={started} bat_ran={bat_ran} err={:?}",
        res.as_ref().err()
    );
    if bat_ran {
        println!(
            "  => CreateProcessW DOES extend an absolute lpApplicationName. The documented \
             'no default extension is assumed' is FALSE, and a CreateProcess route carries the \
             same planting hazard as ShellExecuteEx."
        );
    } else if started {
        panic!("PROBE createprocessw-pathext: INCONCLUSIVE: something started but was not the planted batch.");
    } else {
        // `ERROR_FILE_NOT_FOUND` is the genuine negative measurement: CreateProcessW looked for
        // `tool` and found nothing. Any other error means the harness could not even ask the
        // question, and must not be mislabelled as this exact-image confirmation.
        let err = res.as_ref().expect_err("`started` is false, so `res` is an `Err`");
        assert_eq!(
            err.code(),
            HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
            "PROBE createprocessw-pathext: CreateProcessW failed with an unexpected error (not \
             ERROR_FILE_NOT_FOUND): {err} — the harness could not even ask the question"
        );
        println!(
            "  => CreateProcessW refused a nonexistent extensionless lpApplicationName rather than \
             extending it. The documented exact-image semantics hold: this is the property a \
             CreateProcess-based route would buy."
        );
    }
    mark_test_passed("COSCA_PROBE_MARKERS");
}

/// **Question 2's first step.** Which logon types return a FILTERED token for an account in
/// Administrators, and which return the full one? `LogonUser` is where UAC token filtering is
/// applied, so this is where the chain either starts or dies.
#[test]
#[ignore = "creates a local user account; opt in with --ignored on a throwaway host"]
fn which_logon_types_return_a_filtered_token() {
    require_gate("COSCA_PROBE_ALLOW_ACCOUNTS", "creates and deletes local user accounts");
    let mut measured_admin = false;
    let mut measured_std = false;
    for admin in [true, false] {
        let name = if admin { "coscaprobeadm" } else { "coscaprobestd" };
        let account = match ScratchAccount::create(name, admin) {
            Ok(a) => a,
            Err(e) => {
                println!("PROBE logon-types: could not create {name}: {e}");
                continue;
            }
        };
        let user = wide(&account.user);
        let domain = wide(".");
        let password = wide(&account.password);
        for (label, kind) in [
            ("INTERACTIVE", LOGON32_LOGON_INTERACTIVE),
            ("NETWORK", LOGON32_LOGON_NETWORK),
            ("NETWORK_CLEARTEXT", LOGON32_LOGON_NETWORK_CLEARTEXT),
            ("BATCH", LOGON32_LOGON_BATCH),
            ("SERVICE", LOGON32_LOGON_SERVICE),
        ] {
            let mut h = HANDLE::default();
            // SAFETY: all three wide strings are NUL-terminated and outlive the call.
            let res = unsafe {
                LogonUserW(
                    PCWSTR(user.as_ptr()),
                    PCWSTR(domain.as_ptr()),
                    PCWSTR(password.as_ptr()),
                    kind,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut h,
                )
            };
            let group = if account.admin {
                "Administrators member"
            } else {
                "standard user"
            };
            match res {
                Err(e) => println!("PROBE logon-type {label} ({group}): LogonUser FAILED {e:?}"),
                Ok(()) => {
                    if admin {
                        measured_admin = true;
                    } else {
                        measured_std = true;
                    }
                    let t = Token(h);
                    let mut out = String::new();
                    let _ = writeln!(out, "PROBE logon-type {label} ({group}): LogonUser OK");
                    describe(&mut out, "returned token", t.0);
                    match linked_token(t.0) {
                        Ok(linked) => describe(&mut out, "its TokenLinkedToken", linked.0),
                        Err(e) => {
                            let _ = writeln!(out, "  its TokenLinkedToken: <{e}>");
                        }
                    }
                    print!("{out}");
                }
            }
        }
    }
    // Both accounts must be measured, not just either one: the whole point of running both is the
    // contrast between them, and a single successful logon says nothing about filtering on its own.
    assert!(
        measured_admin,
        "not one LogonUser call for the Administrators-member scratch account returned a token, so \
         that half of the filtering question was never measured"
    );
    assert!(
        measured_std,
        "not one LogonUser call for the standard-user scratch account returned a token, so the \
         contrast against the Administrators account — the whole point of running both — was never \
         measured"
    );
    mark_test_passed("COSCA_PROBE_MARKERS");
}
