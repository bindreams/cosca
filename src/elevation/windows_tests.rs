#[test]
fn detect_reports_windows_os() {
    let h = crate::elevation::plan::Host::detect();
    assert_eq!(h.os, crate::elevation::plan::Os::Windows);
}

#[test]
fn integrity_level_is_always_answerable() {
    // Every Windows process has a mandatory integrity label; a `None` here means the
    // aligned two-call token read is broken, not that the runner lacks an answer. Fail
    // loud rather than let the cross-check below go vacuous.
    assert!(
        super::integrity_level().is_some(),
        "integrity_level() must resolve on any Windows runner"
    );
}

#[test]
fn is_elevated_agrees_with_integrity_level() {
    // Privilege-independent invariant (never assume ambient privilege): a full
    // (elevated) token runs at High+ integrity; a filtered token is Medium. This
    // cross-checks TokenElevation against the independent TokenIntegrityLevel class.
    use windows::Win32::System::SystemServices::SECURITY_MANDATORY_HIGH_RID;
    let elevated = super::is_elevated();
    let rid = super::integrity_level().expect("integrity level must be readable");
    let high = rid >= SECURITY_MANDATORY_HIGH_RID as u32;
    assert_eq!(
        elevated, high,
        "TokenElevation ({elevated}) disagrees with integrity RID {rid:#x} vs High"
    );
}

use crate::command::Command;
use crate::error::Error;
use crate::stdio::Stdio;

fn is_unsupported<T>(r: Result<T, Error>) -> bool {
    matches!(r, Err(Error::Unsupported { .. }))
}

#[test]
fn piped_stdio_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::pipe()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn null_and_merge_stdio_are_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdin(Stdio::null()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));

    let mut c2 = Command::new();
    c2.args(["whoami"]).elevate();
    c2.stderr(Stdio::merge(crate::stdio::Fd::STDOUT)).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c2)));
}

#[test]
fn high_fd_is_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.fd(3, Stdio::pipe_out()).unwrap();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn env_and_contain_are_unsupported() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().env("FOO", "bar");
    assert!(is_unsupported(super::reject_unsupported_config(&c)));

    let mut c2 = Command::new();
    c2.args(["whoami"]).elevate().contain();
    assert!(is_unsupported(super::reject_unsupported_config(&c2)));
}

#[test]
fn inherit_only_is_accepted() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    c.stdout(Stdio::inherit()).unwrap();
    assert!(super::reject_unsupported_config(&c).is_ok());
}

fn win_host(elevated: bool) -> crate::elevation::plan::Host {
    crate::elevation::plan::Host {
        elevated,
        has_tty: false,
        available: crate::elevation::plan::BackendSet::default(),
        os: crate::elevation::plan::Os::Windows,
        arg_max: None,
    }
}

#[test]
fn launch_runas_rejects_bad_config_before_the_short_circuit_regardless_of_privilege() {
    // Piped stdio must fail with Unsupported and never prompt — the gate runs BEFORE the
    // already-elevated short-circuit, so the verdict is identical for elevated=false/true.
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args(["whoami"]).elevate();
        c.stdout(Stdio::pipe()).unwrap();
        assert!(
            is_unsupported(super::launch_runas_with_host(&mut c, &win_host(elevated))),
            "piped elevated config must reject with elevated={elevated}"
        );
    }
}

#[test]
fn commandline_elevated_is_unsupported_on_windows_regardless_of_privilege() {
    for elevated in [false, true] {
        let mut c = Command::new();
        c.commandline("whoami").elevate();
        assert!(is_unsupported(super::launch_runas_with_host(
            &mut c,
            &win_host(elevated)
        )));
    }
}

#[test]
fn already_elevated_inherit_only_is_run_as_is() {
    // The RunAsIs branch: an inherit-only elevated request on an already-elevated host
    // passes the gate and short-circuits (no ShellExecuteEx).
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    assert!(matches!(
        super::launch_runas_with_host(&mut c, &win_host(true)),
        Ok(super::RunasOutcome::AlreadyElevated)
    ));
}

// ===== creation-flag intents on the consent-prompt path =====

/// `ShellExecuteEx` takes a show-command and no creation-flag word, so this is the only knob the
/// consent launch has for the window-suppression intent. Two inputs, two values: a constant
/// implementation fails one of the pair.
#[test]
fn runas_hides_the_window_when_no_window_is_requested() {
    use crate::command::flags::FlagsRequest;
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
    let flags = FlagsRequest {
        no_window: true,
        ..Default::default()
    };
    assert_eq!(super::runas_show_command(&flags), SW_HIDE);
}

#[test]
fn runas_shows_the_window_by_default() {
    use crate::command::flags::FlagsRequest;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    assert_eq!(super::runas_show_command(&FlagsRequest::default()), SW_SHOWNORMAL);
}

/// The consent launch accepts no creation flags at all, so a raw word is refused rather than
/// silently dropped. Stated over the RECORDED state, not "a method was called": `creation_flags(0)`
/// requests nothing, so there is nothing to refuse.
#[test]
fn elevation_rejects_raw_creation_flags() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().creation_flags(0x0000_0040);
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn elevation_accepts_a_zero_creation_flags_word() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().creation_flags(0);
    assert!(super::reject_unsupported_config(&c).is_ok());
}

#[test]
fn elevation_rejects_detached() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().detached();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

#[test]
fn elevation_rejects_breakaway() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().breakaway_from_job();
    assert!(is_unsupported(super::reject_unsupported_config(&c)));
}

/// The one flag intent that survives the gate — which is the whole of the elevated half of the
/// window-suppression feature. Without this leg, a future tightening could take it away again in
/// silence, and the three rejections above would all still pass.
#[test]
fn elevation_accepts_no_window() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().no_window();
    assert!(super::reject_unsupported_config(&c).is_ok());
}
