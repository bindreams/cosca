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

/// The refusal's `detail`, for the tests that assert on the message and not only the variant.
fn unsupported_detail<T: std::fmt::Debug>(r: Result<T, Error>) -> String {
    match r {
        Err(Error::Unsupported { detail, .. }) => detail,
        other => panic!("expected Unsupported, got {other:?}"),
    }
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

/// A Windows-shaped host for the pure seam. Tests below drive [`super::plan_runas`] and never
/// `launch_runas_with_host`: on an `elevated: false` host the latter's fall-through is a real
/// `ShellExecuteExW(runas)`, so a probe that slipped past a check under test would raise a UAC
/// prompt and elevate the probe program under a plain `cargo test`.
fn win_host(elevated: bool) -> crate::elevation::plan::Host {
    crate::elevation::plan::Host {
        elevated,
        has_tty: false,
        available: crate::elevation::plan::BackendSet::default(),
        os: crate::elevation::plan::Os::Windows,
        arg_max: None,
    }
}

/// `prefix` + an interior NUL + `suffix` — the shape Win32 silently truncates at the NUL.
fn nul_between(prefix: &str, suffix: &str) -> std::ffi::OsString {
    use std::os::windows::ffi::OsStringExt;
    std::ffi::OsString::from_wide(
        &prefix
            .encode_utf16()
            .chain([0])
            .chain(suffix.encode_utf16())
            .collect::<Vec<u16>>(),
    )
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
            is_unsupported(super::plan_runas(&c, &win_host(elevated))),
            "piped elevated config must reject with elevated={elevated}"
        );
    }
}

#[test]
fn commandline_elevated_is_unsupported_on_windows_regardless_of_privilege() {
    for elevated in [false, true] {
        let mut c = Command::new();
        c.commandline("whoami").elevate();
        assert!(is_unsupported(super::plan_runas(&c, &win_host(elevated))));
    }
}

/// An argv-less command is not a `commandline()` one. Both of these are reachable from the public
/// builder and neither calls `.commandline()`, so naming it sends the caller to audit a line of
/// their code that does not exist — and says nothing about the program they actually failed to set.
#[test]
fn an_argv_less_command_is_not_reported_as_a_commandline_command() {
    let mut by_executable = Command::new();
    by_executable.executable("x.exe").elevate();

    let mut bare = Command::new();
    bare.elevate();

    for (via, c) in [("executable() only", &by_executable), ("nothing at all", &bare)] {
        match super::plan_runas(c, &win_host(false)) {
            Err(e @ Error::Unsupported { .. }) => {
                let msg = e.to_string();
                assert!(!msg.contains("commandline"), "{via}: none was set, got {msg}");
                assert!(
                    msg.contains("empty command"),
                    "{via}: the refusal must name the missing program, got {msg}"
                );
            }
            other => panic!(
                "{via}: an argv-less elevate() must be refused, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}

/// The affirmative leg. Every other `plan_runas` test asserts a REFUSAL, so all of them would
/// still pass against a seam that refused everything — and "no consent prompt ever happens" is not
/// the property this file is pinning. A clean inherit-only request on an UNELEVATED host must
/// reach `Launch`, with every `SHELLEXECUTEINFOW` string built and NUL-terminated.
#[test]
fn a_clean_unelevated_request_plans_a_launch() {
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let mut c = Command::new();
    c.args(["whoami", "/all"]).elevate();
    let launch = match super::plan_runas(&c, &win_host(false)) {
        Ok(super::RunasStep::Launch(launch)) => launch,
        Ok(super::RunasStep::AlreadyElevated) => panic!("an unelevated host must not short-circuit"),
        Err(e) => panic!("a clean inherit-only request must not be refused: {e:?}"),
    };
    for (field, w) in [
        ("lpVerb", &launch.verb_w),
        ("lpFile", &launch.file_w),
        ("lpParameters", &launch.params_w),
    ] {
        assert_eq!(w.last(), Some(&0), "{field} must be NUL-terminated: {w:?}");
        assert!(w.len() > 1, "{field} must carry the value, not just its terminator");
    }
    assert_eq!(
        launch.dir_w, None,
        "no current_dir() was set, so lpDirectory stays null"
    );
    assert_eq!(launch.show, SW_SHOWNORMAL);
}

#[test]
fn already_elevated_inherit_only_is_run_as_is() {
    // The RunAsIs branch: an inherit-only elevated request on an already-elevated host
    // passes the gate and short-circuits (no ShellExecuteEx).
    let mut c = Command::new();
    c.args(["whoami"]).elevate();
    assert!(matches!(
        super::plan_runas(&c, &win_host(true)),
        Ok(super::RunasStep::AlreadyElevated)
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
    let detail = unsupported_detail(super::reject_unsupported_config(&c));
    crate::error::assert_detail_is_not_hard_wrapped(&detail);
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
    let detail = unsupported_detail(super::reject_unsupported_config(&c));
    crate::error::assert_detail_is_not_hard_wrapped(&detail);
}

#[test]
fn elevation_rejects_breakaway() {
    let mut c = Command::new();
    c.args(["whoami"]).elevate().breakaway_from_job();
    let detail = unsupported_detail(super::reject_unsupported_config(&c));
    crate::error::assert_detail_is_not_hard_wrapped(&detail);
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

// ===== interior NULs must be refused, not silently truncated =====

/// `PCWSTR` stops at the first NUL, so every `SHELLEXECUTEINFOW` string field is TRUNCATED rather
/// than rejected when it contains one. Each truncation changes what an ELEVATED process does:
/// a different image loads, a different working directory applies, or the argument line is cut
/// short. The raw `CreateProcessW` backend already refuses all three via its own NUL checks, so
/// leaving them unchecked here would make THIS divergence depend on whether `.elevate()` was
/// called. A separate, still-open divergence — `ShellExecuteEx` resolving a program
/// `CreateProcessW` would refuse, whether by PATHEXT-completing an extension-less token or by
/// another registered `runas` association (`.lnk`, `.vbs`, `.msc`, …) — is not closed here.
///
/// Tested directly on the builder rather than through `ShellExecuteExW`, so it needs no UAC
/// prompt and no elevated child.
#[test]
fn wide_nul_refuses_an_interior_nul_in_any_value() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    // A value whose FIRST unit is NUL, and one where the NUL hides in the middle — the second is
    // the dangerous shape, because it looks like a perfectly ordinary path until Win32 cuts it.
    for units in [
        vec![0u16],
        "C:\\a\\b.exe\0junk".encode_utf16().collect::<Vec<u16>>(),
        "D:\\work\0junk".encode_utf16().collect::<Vec<u16>>(),
    ] {
        let value = OsString::from_wide(&units);
        let got = super::wide_nul("probe field", &value);
        assert!(
            got.is_err(),
            "an interior NUL must be refused, not truncated to {:?}",
            value.to_string_lossy().split('\0').next().unwrap()
        );
        match got.unwrap_err() {
            Error::Io(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e:?}");
                assert!(
                    e.to_string().contains("probe field"),
                    "refusal must name the field: {e}"
                );
            }
            other => panic!("expected Io(InvalidInput), got {other:?}"),
        }
    }
}

/// The ordinary case still works, so the guard above is gating NULs rather than rejecting
/// everything — and the result really is NUL-TERMINATED, which is what `PCWSTR` requires.
#[test]
fn wide_nul_accepts_an_ordinary_value_and_terminates_it() {
    let w = super::wide_nul("program path", std::ffi::OsStr::new("C:\\tools\\app.exe")).unwrap();
    assert_eq!(w.last(), Some(&0), "the buffer must be NUL-terminated: {w:?}");
    assert!(!w[..w.len() - 1].contains(&0), "no interior NUL in a clean value");
}

/// THE WIRING of the fallible call sites, not the helper. `wide_nul` being correct is worthless
/// if a field is built by an inline `encode_wide().chain(once(0))` instead — reverting any single
/// call site to that leaves the helper's own tests green, so this drives `plan_runas` and pins
/// that the truncating value is actually refused, AND blamed on the right field, where it is used.
///
/// A call site that ESCAPED the check comes back `Ok(Launch)`, which the fall-through arm below
/// panics on. That is the whole reason this drives the pure seam: on `launch_runas_with_host` the
/// same escape would hand the probe to `ShellExecuteExW` and raise a UAC prompt under `cargo test`.
///
/// One leg per field a caller can poison — `lpFile`, `lpParameters`, `lpDirectory`. A single-argv,
/// no-cwd probe only reaches `lpFile`: with an empty joined parameter line and `cmd.cwd() == None`,
/// dropping either of the other two checks leaves every test green, which is exactly the gap this
/// test exists to close. Each leg also asserts the detail names ITS field, not just `InvalidInput`
/// — a swap that trips the right error kind but blames the wrong field would otherwise still pass.
///
/// The `lpParameters` leg lands on the per-ELEMENT check, which is what can name `argument 1`;
/// `plan_runas` has two further `wide_nul(...)?` sites with no failing input reachable from the
/// public builder (`verb_w` is the literal `"runas"`, and `params_w` is the join of elements this
/// leg already checked), so neither is tested here.
///
/// Run for both privilege levels because the check now sits above the short-circuit: an
/// already-elevated caller must get the same refusal, not a silent `AlreadyElevated`.
#[test]
fn launch_runas_refuses_a_truncating_nul_regardless_of_privilege() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let nul_path = OsString::from_wide(
        &r"Z:\cosca-nonexistent\x.exe"
            .encode_utf16()
            .chain([0])
            .chain("junk".encode_utf16())
            .collect::<Vec<u16>>(),
    );

    let clean = OsString::from(r"Z:\cosca-nonexistent\x.exe");
    for elevated in [false, true] {
        // lpFile, lpParameters, lpDirectory — one probe each, every other field clean so the
        // refusal can only have come from the field under test.
        let mut by_program = Command::new();
        by_program.args([nul_path.clone()]).elevate();

        let mut by_argument = Command::new();
        by_argument.args([clean.clone(), nul_path.clone()]).elevate();

        let mut by_cwd = Command::new();
        by_cwd.args([clean.clone()]).current_dir(&nul_path).elevate();

        for (field, needle, c) in [
            ("lpFile", "program path", &by_program),
            ("lpParameters", "argument 1", &by_argument),
            ("lpDirectory", "working directory", &by_cwd),
        ] {
            match super::plan_runas(c, &win_host(elevated)) {
                Err(Error::Io(e)) => {
                    assert_eq!(
                        e.kind(),
                        std::io::ErrorKind::InvalidInput,
                        "elevated={elevated} {field}: expected the NUL refusal, got {e:?}"
                    );
                    assert!(
                        e.to_string().contains(needle),
                        "elevated={elevated} {field}: refusal must name the field ({needle:?}), got {e}"
                    );
                }
                other => panic!(
                    "elevated={elevated} {field}: a truncating NUL must be refused at the call \
                     site, got {:?}",
                    other.map(|_| "Ok")
                ),
            }
        }
    }
}

/// One predicate, one sentence. The elevated path and the raw `CreateProcessW` backend refuse an
/// interior NUL for the same reason on the same field, and restating it per path is what let
/// "elevated program path" drift away from "program path" — a wording difference a caller reads as
/// two different defects.
#[test]
fn the_elevated_and_raw_paths_word_the_nul_refusal_identically() {
    let token = nul_between(r"C:\tools\x.exe", "junk");

    let mut c = Command::new();
    c.args([token.clone()]).elevate();
    let elevated = match super::plan_runas(&c, &win_host(false)) {
        Err(Error::Io(e)) => e.to_string(),
        other => panic!(
            "a truncating program path must be refused, got {:?}",
            other.map(|_| "Ok")
        ),
    };

    let raw = crate::child::spawn::windows_raw::resolve::ensure_no_nul_wide("program path", &token)
        .expect_err("the raw backend refuses the same token")
        .to_string();

    assert_eq!(elevated, raw, "one defect, described two ways");
}

/// A `.bat`/`.cmd` SPELLED IN THE TOKEN must be refused here as on every other backend.
/// `ShellExecuteEx`'s `runas` resolves the `batfile` association through `cmd.exe` and substitutes
/// `lpParameters` into `%*` unescaped, while `join_wide` quotes only for whitespace — so an
/// argument like `a&calc` is command injection into an ELEVATED shell (CVE-2024-24576).
///
/// Scope, so this test is not read as proving more than it does: the gate keys on the caller's
/// string, and `ShellExecuteEx` resolves the file. An extension-less `args(["setup", "a&calc"])`
/// passes it and can still be PATHEXT-completed to `setup.bat` — see `plan_runas`.
///
/// Privilege-independent for the same reason as the config gate: the already-elevated caller
/// falls through to a backend that refuses this, so refusing it here keeps the verdict a property
/// of the request rather than of the host.
#[test]
fn launch_runas_refuses_a_batch_program_regardless_of_privilege() {
    for elevated in [false, true] {
        for probe in ["setup.bat", "setup.cmd", "SETUP.BAT"] {
            let mut c = Command::new();
            c.args([probe, "a&calc"]).elevate();
            assert!(
                is_unsupported(super::plan_runas(&c, &win_host(elevated)).map(|_| ())),
                "elevated={elevated}: {probe:?} must be refused before ShellExecuteEx hands it to cmd.exe"
            );
        }
    }
}

/// A NUL-truncated path that only LOOKS like a batch file (`C:\tools\setup` + NUL + `.bat`): Win32
/// launches `C:\tools\setup`, a different program than the caller named and no batch file at all.
/// Whichever gate refuses it must therefore say NUL and not CVE-2024-24576, or the caller is sent
/// to audit a vector they do not carry while the wrong image still runs elevated.
#[test]
fn nul_bearing_batch_looking_path_is_diagnosed_as_a_nul_not_a_batch_refusal() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let nul_bat = OsString::from_wide(
        &r"C:\tools\setup"
            .encode_utf16()
            .chain([0])
            .chain(".bat".encode_utf16())
            .collect::<Vec<u16>>(),
    );
    // `\0` is not a path separator, so `extension()` reads `bat` straight through it — the reason
    // the batch gate cannot key on the extension, and the reason it has nothing to say here.
    assert_eq!(
        std::path::Path::new(&nul_bat).extension().map(|e| e.to_string_lossy()),
        Some("bat".into()),
        "premise: the token's extension is misleading"
    );
    assert!(
        matches!(
            crate::child::spawn::reject_batch_path(std::path::Path::new(&nul_bat)),
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::InvalidInput
        ),
        "premise: the shared gate refuses this as a NUL too, never as a batch file"
    );
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args([nul_bat.clone()]).elevate();
        match super::plan_runas(&c, &win_host(elevated)) {
            Err(Error::Io(e)) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "elevated={elevated}: expected the NUL refusal, got {e:?}"
                );
                // The kind alone lets "right kind, blamed the wrong field" pass — which is the
                // misattribution this test exists to catch, one level down.
                assert!(
                    e.to_string().contains("program path"),
                    "elevated={elevated}: the refusal must blame the program path, got {e}"
                );
            }
            other => panic!(
                "elevated={elevated}: a NUL-bearing batch-looking path must be diagnosed as a NUL, \
                 got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}

/// The mirror shape: `setup.bat` + NUL + `junk`, which Win32 truncates back to the real batch file
/// `setup.bat`. Its extension is the one the batch rule could plausibly claim, so this pins that
/// the caller is still told about the NUL — their actual defect — and not about batch escaping.
#[test]
fn a_nul_after_a_batch_extension_is_blamed_on_the_nul_not_the_batch_gate() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let bat_nul = OsString::from_wide(
        &r"C:\tools\setup.bat"
            .encode_utf16()
            .chain([0])
            .chain("junk".encode_utf16())
            .collect::<Vec<u16>>(),
    );
    // Premise: the shared gate refuses this token too, as a NUL — so an `Unsupported` arriving
    // below could only be the batch rule jumping the NUL it is ordered behind.
    assert!(
        matches!(
            crate::child::spawn::reject_batch_path(std::path::Path::new(&bat_nul)),
            Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::InvalidInput
        ),
        "premise: the shared gate refuses this as a NUL"
    );
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args([bat_nul.clone(), OsString::from("a&calc")]).elevate();
        match super::plan_runas(&c, &win_host(elevated)) {
            Err(Error::Io(e)) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "elevated={elevated}: expected the NUL refusal, got {e:?}"
                );
                assert!(
                    e.to_string().contains("program path"),
                    "elevated={elevated}: the refusal must blame the program path, got {e}"
                );
            }
            other => panic!(
                "elevated={elevated}: a NUL that truncates back to a real batch file must be \
                 blamed on the NUL, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}

/// WHICH field a MULTI-poisoned request names. Every leg above poisons exactly one, so none of
/// them pins the order: with the per-element argv loop running ahead of the program's own check,
/// `args(["setup.bat\0junk", "x\0y"])` came back "argument 1" and never mentioned that the program
/// path — the field deciding which image runs ELEVATED — is truncating too. NUL on the program
/// path first, for attribution, as on the raw backend.
#[test]
fn a_poisoned_program_path_is_named_before_a_poisoned_argument_or_cwd() {
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args([nul_between(r"C:\tools\setup.bat", "junk"), nul_between("x", "y")])
            .current_dir(nul_between(r"C:\work", "junk"))
            .elevate();
        match super::plan_runas(&c, &win_host(elevated)) {
            Err(Error::Io(e)) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "elevated={elevated}: expected the NUL refusal, got {e:?}"
                );
                assert!(
                    e.to_string().contains("program path"),
                    "elevated={elevated}: the program path outranks the other poisoned fields, got {e}"
                );
            }
            other => panic!(
                "elevated={elevated}: a truncating NUL must be refused, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}

/// The cwd leg of that same rule, which no test above reaches: each multi-field probe poisons the
/// program too, so the program's own check short-circuits before `lpDirectory` is ever built. A
/// clean `.bat` with a truncating `current_dir()` is a NUL the caller can fix, and "batch escaping
/// is not implemented" would never mention that `lpDirectory` truncates as well.
#[test]
fn a_poisoned_working_directory_is_named_before_the_batch_gate() {
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args([std::ffi::OsString::from(r"C:\tools\setup.bat")])
            .current_dir(nul_between(r"C:\work", "junk"))
            .elevate();
        match super::plan_runas(&c, &win_host(elevated)) {
            Err(Error::Io(e)) => {
                assert_eq!(
                    e.kind(),
                    std::io::ErrorKind::InvalidInput,
                    "elevated={elevated}: expected the NUL refusal, got {e:?}"
                );
                assert!(
                    e.to_string().contains("working directory"),
                    "elevated={elevated}: the refusal must name the working directory, got {e}"
                );
            }
            other => panic!(
                "elevated={elevated}: the cwd's NUL must be refused before the batch gate, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}

/// The other side of that ordering: the batch gate must not jump ahead of a poisoned ARGUMENT
/// either. A clean `.bat` with a truncating argument is a NUL the caller can fix, and
/// "batch escaping is not implemented" would hide it.
#[test]
fn a_poisoned_argument_is_named_before_the_batch_gate() {
    for elevated in [false, true] {
        let mut c = Command::new();
        c.args([std::ffi::OsString::from(r"C:\tools\setup.bat"), nul_between("x", "y")])
            .elevate();
        match super::plan_runas(&c, &win_host(elevated)) {
            Err(Error::Io(e)) => assert!(
                e.to_string().contains("argument 1"),
                "elevated={elevated}: the refusal must name the poisoned argument, got {e}"
            ),
            other => panic!(
                "elevated={elevated}: the argument's NUL must be refused before the batch gate, got {:?}",
                other.map(|_| "Ok")
            ),
        }
    }
}
