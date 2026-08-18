//! Truth tables for the composed creation-flag word. Pure: nothing here spawns anything, so
//! every rule is pinned across the whole request space rather than at the shapes a live spawn
//! happens to take.
#![cfg(windows)]

use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
    IDLE_PRIORITY_CLASS,
};

use super::{windows_spawn, FlagsRequest, SpawnBackend};
use crate::containment::{ContainMode, ContainRequest, Nesting};
use crate::error::Error;

fn uncontained() -> ContainRequest {
    ContainRequest {
        mode: None,
        nesting: Nesting::Mark,
    }
}

fn contained() -> ContainRequest {
    ContainRequest {
        mode: Some(ContainMode::Strongest),
        nesting: Nesting::Mark,
    }
}

fn word(contain: &ContainRequest, flags: FlagsRequest, is_root: bool, backend: SpawnBackend) -> u32 {
    windows_spawn(contain, flags, is_root, backend)
        .expect("this request shape is allowed")
        .creation_flags
}

fn refusal(flags: FlagsRequest) -> String {
    match windows_spawn(&uncontained(), flags, false, SpawnBackend::Std) {
        Ok(w) => panic!("expected a refusal, got the word {:#x}", w.creation_flags),
        Err(Error::Unsupported { detail, .. }) => detail,
        Err(other) => panic!("expected Unsupported, got {other:?}"),
    }
}

/// A caller's raw word reaches an uncontained spawn untouched. This is also the shape
/// `prepare`'s `mode.is_none()` early return used to drop entirely.
#[test]
fn an_uncontained_std_request_carries_only_the_callers_flags() {
    let flags = FlagsRequest {
        raw: IDLE_PRIORITY_CLASS.0,
        ..Default::default()
    };
    assert_eq!(
        word(&uncontained(), flags, false, SpawnBackend::Std),
        IDLE_PRIORITY_CLASS.0,
        "an uncontained std spawn supplies nothing of its own"
    );
}

/// The containment decision and the caller's intent are ORed, not chosen between: a `Strongest`
/// root keeps its suspend and its process group while also getting the caller's suppression.
#[test]
fn contained_root_flags_and_caller_flags_compose() {
    let flags = FlagsRequest {
        no_window: true,
        ..Default::default()
    };
    assert_eq!(
        word(&contained(), flags, true, SpawnBackend::Std),
        CREATE_SUSPENDED.0 | CREATE_NEW_PROCESS_GROUP.0 | CREATE_NO_WINDOW.0,
    );
}

/// The two bits the raw `CreateProcessW` backend cannot spawn without are supplied by
/// `windows_spawn` for that backend and by nothing else, so no backend ORs anything on
/// afterwards.
///
/// **This pins a cosca-side difference only.** Per `library/std/src/sys/process/windows.rs`, std
/// ORs `CREATE_UNICODE_ENVIRONMENT` into whatever word it was given at spawn time, so this test
/// does not say the OS receives a `Std` word without it — only that cosca does not supply it.
#[test]
fn cosca_supplies_the_structural_bits_only_on_the_raw_backend() {
    let flags = FlagsRequest {
        no_window: true,
        ..Default::default()
    };
    let std_word = word(&contained(), flags, true, SpawnBackend::Std);
    let raw_word = word(&contained(), flags, true, SpawnBackend::Raw);
    assert_eq!(
        raw_word ^ std_word,
        CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0,
        "the backends differ by exactly the two structural bits",
    );
}

/// Both intents are emitted; neither normalizes the other away. Measured: a child with both
/// behaves as detached, and cosca reports what it asked for rather than second-guessing it.
#[test]
fn detached_and_no_window_both_appear() {
    let flags = FlagsRequest {
        detached: true,
        no_window: true,
        ..Default::default()
    };
    let w = word(&uncontained(), flags, false, SpawnBackend::Std);
    assert_eq!(w, DETACHED_PROCESS.0 | CREATE_NO_WINDOW.0);
}

/// The breakaway bit is emitted from the request alone, never from a reading of the ambient job:
/// a probe taken before the spawn could go stale in the gap, and omitting the bit would silently
/// leave the child in a job the caller asked it to escape. Asserted for both backends and both
/// root-nesses so no backend can drop it.
#[test]
fn a_breakaway_request_always_emits_the_bit() {
    let flags = FlagsRequest {
        breakaway_from_job: true,
        ..Default::default()
    };
    for backend in [SpawnBackend::Std, SpawnBackend::Raw] {
        for is_root in [true, false] {
            let w = word(&uncontained(), flags, is_root, backend);
            assert_ne!(
                w & CREATE_BREAKAWAY_FROM_JOB.0,
                0,
                "{backend:?}/is_root={is_root} dropped the breakaway request"
            );
        }
    }
}

/// An uncontained word does not depend on the root marker at all, which is what licenses
/// `prepare` composing the word once, above its containment branch.
#[test]
fn an_uncontained_word_ignores_is_root() {
    let flags = FlagsRequest {
        no_window: true,
        raw: IDLE_PRIORITY_CLASS.0,
        ..Default::default()
    };
    assert_eq!(
        word(&uncontained(), flags, true, SpawnBackend::Std),
        word(&uncontained(), flags, false, SpawnBackend::Std),
    );
}

/// Every reserved bit is refused, and the refusal names the bit symbolically — a caller who
/// passed `0x0800_0000` should not have to look up which flag that was.
///
/// The list is written out here rather than read from the production table, so dropping a row
/// from that table fails this test instead of silently un-reserving a bit.
#[test]
fn each_reserved_bit_is_refused_by_name() {
    let reserved = [
        (DEBUG_PROCESS.0, "DEBUG_PROCESS"),
        (DEBUG_ONLY_THIS_PROCESS.0, "DEBUG_ONLY_THIS_PROCESS"),
        (CREATE_SUSPENDED.0, "CREATE_SUSPENDED"),
        (DETACHED_PROCESS.0, "DETACHED_PROCESS"),
        (CREATE_NEW_CONSOLE.0, "CREATE_NEW_CONSOLE"),
        (CREATE_NEW_PROCESS_GROUP.0, "CREATE_NEW_PROCESS_GROUP"),
        (CREATE_UNICODE_ENVIRONMENT.0, "CREATE_UNICODE_ENVIRONMENT"),
        (EXTENDED_STARTUPINFO_PRESENT.0, "EXTENDED_STARTUPINFO_PRESENT"),
        (CREATE_BREAKAWAY_FROM_JOB.0, "CREATE_BREAKAWAY_FROM_JOB"),
    ];
    for (bit, name) in reserved {
        let detail = refusal(FlagsRequest {
            raw: bit,
            ..Default::default()
        });
        assert!(detail.contains(name), "refusal for {bit:#x} must name {name}: {detail}");
    }
}

/// Two reserved bits at once name both, so a caller fixes one call instead of iterating through
/// a refusal per bit.
#[test]
fn several_reserved_bits_are_all_named() {
    let detail = refusal(FlagsRequest {
        raw: CREATE_SUSPENDED.0 | CREATE_NO_WINDOW.0,
        ..Default::default()
    });
    assert!(detail.contains("CREATE_SUSPENDED"), "{detail}");
    assert!(detail.contains("CREATE_NO_WINDOW"), "{detail}");
}

/// The two bits the raw backend supplies structurally are themselves reserved, so a caller can
/// never set one and have it doubled — or clear one the backend cannot spawn without.
#[test]
fn the_structural_bits_are_reserved() {
    for (bit, name) in [
        (CREATE_UNICODE_ENVIRONMENT.0, "CREATE_UNICODE_ENVIRONMENT"),
        (EXTENDED_STARTUPINFO_PRESENT.0, "EXTENDED_STARTUPINFO_PRESENT"),
    ] {
        let detail = refusal(FlagsRequest {
            raw: bit,
            ..Default::default()
        });
        assert!(detail.contains(name), "{detail}");
    }
}

/// The three containment shapes must not all report the same cooperative-signal mechanism: an
/// uncontained spawn leads no group, while both contained shapes do. Asserted on the COMPOSED
/// word, which is the only word any spawn path derives a mechanism from.
#[test]
fn the_composed_word_reports_a_different_mechanism_for_each_containment_shape() {
    use crate::containment::windows::mechanism_from_flags;
    use crate::graceful::GracefulMechanism;

    let none = FlagsRequest::default();
    assert_eq!(
        mechanism_from_flags(word(&uncontained(), none, true, SpawnBackend::Std)),
        GracefulMechanism::None,
        "an uncontained spawn passes no group flag, so it leads no group"
    );
    assert_eq!(
        mechanism_from_flags(word(&contained(), none, true, SpawnBackend::Std)),
        GracefulMechanism::ConsoleGroup,
        "a Strongest root spawns suspended into its own group"
    );
    assert_eq!(
        mechanism_from_flags(word(&contained(), none, false, SpawnBackend::Std)),
        GracefulMechanism::ConsoleGroup,
        "a nested spawn leads its own group too"
    );
    assert_eq!(
        mechanism_from_flags(word(
            &contained(),
            FlagsRequest {
                no_window: true,
                ..Default::default()
            },
            true,
            SpawnBackend::Std
        )),
        GracefulMechanism::OtherConsoleGroup,
        "window suppression puts the child's group in a console of its own"
    );
}

// ===== breakaway: the pre-spawn rule and the post-failure classifier =====

use crate::containment::windows::JobBreakaway;

fn breakaway() -> FlagsRequest {
    FlagsRequest {
        breakaway_from_job: true,
        ..Default::default()
    }
}

/// `ERROR_ACCESS_DENIED` in the two encodings that reach the classifier: the std path returns the
/// bare Win32 code, the raw backends convert a `windows::core::Error` whose `raw_os_error` is the
/// HRESULT. Derived from the documented `HRESULT_FROM_WIN32` mapping, not from this crate's own
/// output, so a bug in that conversion cannot make the test agree with itself.
fn access_denied_encodings() -> [i32; 2] {
    let win32 = windows::Win32::Foundation::ERROR_ACCESS_DENIED.0 as i32;
    [win32, windows::core::HRESULT::from_win32(win32 as u32).0]
}

fn io_err(code: i32) -> Error {
    Error::Io(std::io::Error::from_raw_os_error(code))
}

/// Breaking away while contained is refused for a ROOT and a NESTED request alike, so the verdict
/// is order- and root-independent: making it depend on root-ness would mean the identical
/// `Command` succeeds in one process and fails in a nested one.
#[test]
fn breakaway_with_containment_is_refused() {
    for is_root in [true, false] {
        let err = windows_spawn(&contained(), breakaway(), is_root, SpawnBackend::Std)
            .expect_err("breakaway plus containment is refused");
        assert!(
            matches!(err, Error::Unsupported { .. }),
            "is_root={is_root}: got {err:?}"
        );
    }
}

/// F1: with a forbidding ambient job, an emitted breakaway bit GUARANTEES an access-denied
/// failure, so the request is a sufficient cause of the failure the caller just got.
///
/// The detail names the measured limit, the request, and the first-refusal qualifier. It must not
/// claim the request was the spawn's only problem: the breakaway check runs before the image is
/// resolved, so a genuine "no such program" is masked by it.
#[test]
fn a_forbidding_job_turns_access_denied_into_a_typed_containment_error() {
    for code in access_denied_encodings() {
        let out = super::classify_spawn_denial(io_err(code), breakaway(), JobBreakaway::Forbidden);
        let Error::Containment { detail } = out else {
            panic!("encoding {code:#x}: expected Containment, got {out:?}");
        };
        assert!(detail.contains("JOB_OBJECT_LIMIT_BREAKAWAY_OK"), "{detail}");
        assert!(detail.contains("breakaway_from_job()"), "{detail}");
        assert!(detail.contains("FIRST"), "{detail}");
    }
}

/// F2. Measured (Windows 11 26100, 2026-08-18): a silent-breakaway job ACCEPTS the flag, so no
/// breakaway request can reach the classifier from such a job at all. The verdict exists solely
/// to stop that job being misread as `Forbidden`, whose message would be wrong about the world —
/// a silent-breakaway job does not forbid children from leaving, it removes them itself.
#[test]
fn the_silent_breakaway_verdict_keeps_the_raw_io_error() {
    for code in access_denied_encodings() {
        let out = super::classify_spawn_denial(io_err(code), breakaway(), JobBreakaway::SilentBreakaway);
        assert!(matches!(out, Error::Io(_)), "encoding {code:#x}: got {out:?}");
    }
}

/// F3: the typed variant must never assert a cause the process just measured to be false — nor
/// one it could not measure at all.
#[test]
fn a_contradicted_or_unmeasurable_probe_keeps_the_raw_io_error() {
    for job in [JobBreakaway::Permitted, JobBreakaway::NotInJob, JobBreakaway::Unknown] {
        for code in access_denied_encodings() {
            let out = super::classify_spawn_denial(io_err(code), breakaway(), job);
            assert!(matches!(out, Error::Io(_)), "{job:?}/{code:#x}: got {out:?}");
        }
    }
}

/// F4: an unrelated failure code stays itself whatever the ambient job looks like.
#[test]
fn an_unrelated_failure_code_is_never_reclassified() {
    let not_found = windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.0 as i32;
    for job in [
        JobBreakaway::Forbidden,
        JobBreakaway::Permitted,
        JobBreakaway::SilentBreakaway,
        JobBreakaway::NotInJob,
        JobBreakaway::Unknown,
    ] {
        let out = super::classify_spawn_denial(io_err(not_found), breakaway(), job);
        assert!(matches!(out, Error::Io(_)), "{job:?}: got {out:?}");
    }
}

/// F4, the other half: an access-denied spawn with NO breakaway request is never blamed on a job.
/// Without this, an unrelated denial would be rewritten into a containment error naming a flag
/// that was never submitted to anything.
#[test]
fn a_spawn_denial_without_a_breakaway_request_is_never_reclassified() {
    for job in [
        JobBreakaway::Forbidden,
        JobBreakaway::Permitted,
        JobBreakaway::SilentBreakaway,
        JobBreakaway::NotInJob,
        JobBreakaway::Unknown,
    ] {
        for code in access_denied_encodings() {
            let out = super::classify_spawn_denial(io_err(code), FlagsRequest::default(), job);
            assert!(matches!(out, Error::Io(_)), "{job:?}/{code:#x}: got {out:?}");
        }
    }
}
