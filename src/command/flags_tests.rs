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
