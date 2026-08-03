//! Pure validation and error mapping for a persisted identity record. Compiled and run on
//! EVERY host, so the Linux-only boot-session branches are exercised on Windows and macOS
//! CI too.

use super::{reject, scope_error, validate, Platform, ProcessIdRecord, Scope, ScopeReadError, RECORD_VERSION};
use crate::error::{Error, RecordErrorKind};

/// A well-formed Linux record: boot session `36c3…`, pid namespace 4026531836.
fn linux_record() -> ProcessIdRecord {
    ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::Linux,
        pid: 4242,
        token: 162_431_157,
        boot_id: Some("36c39237-f06e-4e88-a74d-ea99d42b817c".into()),
        pid_ns: Some(4_026_531_836),
    }
}

fn linux_scope() -> Scope {
    Scope {
        boot_id: Some("36c39237-f06e-4e88-a74d-ea99d42b817c".into()),
        pid_ns: Some(4_026_531_836),
    }
}

/// A well-formed Windows record. The token is a real measured creation FILETIME,
/// deliberately larger than 2^53.
fn windows_record() -> ProcessIdRecord {
    ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::Windows,
        pid: 4242,
        token: 134_301_578_477_907_396,
        boot_id: None,
        pid_ns: None,
    }
}

#[test]
fn a_matching_linux_record_validates() {
    assert_eq!(
        validate(&linux_record(), &Platform::Linux, &linux_scope()),
        Ok((4242, 162_431_157))
    );
}

#[test]
fn a_windows_record_validates_with_an_empty_scope() {
    assert_eq!(
        validate(&windows_record(), &Platform::Windows, &Scope::none()),
        Ok((4242, 134_301_578_477_907_396))
    );
}

#[test]
fn a_linux_record_is_rejected_on_windows() {
    // The measured hazard: Linux jiffies are boot-relative and would be compared against
    // an absolute FILETIME. Must never be accepted.
    assert_eq!(
        validate(&linux_record(), &Platform::Windows, &Scope::none()),
        Err(RecordErrorKind::ForeignPlatform)
    );
}

#[test]
fn a_windows_record_is_rejected_on_linux() {
    assert_eq!(
        validate(&windows_record(), &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::ForeignPlatform)
    );
}

#[test]
fn an_unknown_platform_tag_is_rejected_not_a_parse_failure() {
    let mut r = linux_record();
    r.platform = Platform::Other("freebsd".into());
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::ForeignPlatform)
    );
}

#[test]
fn an_unknown_version_is_rejected_before_anything_else() {
    let mut r = linux_record();
    r.version = RECORD_VERSION + 1;
    // Also make it foreign-platform, to pin that VERSION is checked FIRST: a future
    // format may reuse these fields with different meanings.
    r.platform = Platform::Other("freebsd".into());
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::UnknownVersion)
    );
}

#[test]
fn a_version_zero_record_is_rejected() {
    let mut r = linux_record();
    r.version = 0;
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::UnknownVersion)
    );
}

#[test]
fn a_linux_record_from_a_different_boot_is_rejected() {
    // After a reboot the jiffy counter restarts, so a saved token would alias onto whatever
    // now occupies the pid.
    let scope = Scope {
        boot_id: Some("00000000-0000-0000-0000-000000000000".into()),
        pid_ns: Some(4_026_531_836),
    };
    assert_eq!(
        validate(&linux_record(), &Platform::Linux, &scope),
        Err(RecordErrorKind::ForeignBootSession)
    );
}

#[test]
fn a_linux_record_from_a_different_pid_namespace_is_rejected() {
    // Measured: a container shares the host's boot_id but has its own pid namespace,
    // so boot_id alone does not scope the pid.
    let scope = Scope {
        boot_id: Some("36c39237-f06e-4e88-a74d-ea99d42b817c".into()),
        pid_ns: Some(4_026_532_417),
    };
    assert_eq!(
        validate(&linux_record(), &Platform::Linux, &scope),
        Err(RecordErrorKind::ForeignPidNamespace)
    );
}

#[test]
fn a_linux_record_without_a_boot_id_is_rejected() {
    let mut r = linux_record();
    r.boot_id = None;
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::MissingBootSession)
    );
}

#[test]
fn a_linux_record_without_a_pid_namespace_is_rejected() {
    let mut r = linux_record();
    r.pid_ns = None;
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::MissingPidNamespace)
    );
}

#[test]
fn scope_fields_the_host_does_not_use_are_ignored() {
    // A Windows record that somehow carries Linux scope fields is still valid on Windows:
    // the platform matched, and this host has no boot session to compare against.
    let mut r = windows_record();
    r.boot_id = Some("36c39237-f06e-4e88-a74d-ea99d42b817c".into());
    r.pid_ns = Some(4_026_531_836);
    assert_eq!(
        validate(&r, &Platform::Windows, &Scope::none()),
        Ok((4242, 134_301_578_477_907_396))
    );
}

#[test]
fn platform_tags_round_trip_through_their_wire_strings() {
    for p in [Platform::Linux, Platform::MacOs, Platform::Windows] {
        assert_eq!(Platform::from_wire(p.as_str()), p);
    }
    assert_eq!(Platform::from_wire("freebsd"), Platform::Other("freebsd".into()));
    assert_eq!(Platform::Other("freebsd".into()).as_str(), "freebsd");
}

#[test]
fn the_wire_strings_are_the_documented_ones() {
    // Pinned literals: these strings are the persisted format and may never drift.
    assert_eq!(Platform::Linux.as_str(), "linux");
    assert_eq!(Platform::MacOs.as_str(), "macos");
    assert_eq!(Platform::Windows.as_str(), "windows");
}

#[test]
fn platform_current_names_this_host() {
    // Expected value from `std::env::consts::OS`, an independent fact about the build
    // target — NOT a second copy of `Platform::current`'s own cfg branching, which would
    // only prove the two agree with each other. The three wire strings were chosen to
    // match `consts::OS` exactly, so this is a straight comparison.
    assert_eq!(Platform::current().as_str(), std::env::consts::OS);
}

// A pid is data from a file like everything else in the record, and the crate's Unix code
// treats "not a single-process target" as impossible: `src/wait/linux.rs` does
// `Pid::from_raw(id.pid() as i32).expect("a resolvable ProcessId is never pid 0")`, which
// PANICS on 0, and `src/identity/probe.rs` documents that a value above `i32::MAX` wraps
// negative, where `kill(-N, sig)` hits a whole process group. Restoring such a pid must be
// a typed rejection, never a panic — and never a signal to the wrong target.

#[test]
fn a_unix_record_with_pid_zero_is_rejected() {
    let mut r = linux_record();
    r.pid = 0;
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::InvalidPid)
    );
}

#[test]
fn a_macos_record_with_pid_zero_is_rejected() {
    // macOS is the platform where pid 0 actually RESOLVES (`kernel_task`), so the check
    // cannot be left to the later existence probe.
    let r = ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::MacOs,
        pid: 0,
        token: 1,
        boot_id: None,
        pid_ns: None,
    };
    assert_eq!(
        validate(&r, &Platform::MacOs, &Scope::none()),
        Err(RecordErrorKind::InvalidPid)
    );
}

#[test]
fn a_unix_record_with_a_pid_above_i32_max_is_rejected() {
    let mut r = linux_record();
    r.pid = u32::MAX;
    assert_eq!(
        validate(&r, &Platform::Linux, &linux_scope()),
        Err(RecordErrorKind::InvalidPid)
    );
}

#[test]
fn a_windows_record_with_pid_zero_is_rejected() {
    let mut r = windows_record();
    r.pid = 0;
    assert_eq!(
        validate(&r, &Platform::Windows, &Scope::none()),
        Err(RecordErrorKind::InvalidPid)
    );
}

#[test]
fn a_windows_record_with_a_pid_above_i32_max_is_accepted() {
    // Deliberate asymmetry: a Windows pid is a full `DWORD` and is never a `kill(2)`
    // target, so the `i32` ceiling that protects the Unix backends does not apply here.
    let mut r = windows_record();
    r.pid = u32::MAX;
    assert_eq!(
        validate(&r, &Platform::Windows, &Scope::none()),
        Ok((u32::MAX, 134_301_578_477_907_396))
    );
}

#[test]
fn the_pid_check_runs_after_the_platform_check() {
    // A pid-0 record from the wrong platform is ForeignPlatform: the pid rule is chosen by
    // platform, so it may not be applied before the platform is known to match.
    let mut r = linux_record();
    r.pid = 0;
    assert_eq!(
        validate(&r, &Platform::Windows, &Scope::none()),
        Err(RecordErrorKind::ForeignPlatform)
    );
}

#[test]
fn a_scope_mismatch_names_the_values_that_diverged() {
    // `kind` alone tells an operator the category; the detail has to say WHICH value
    // failed to match, the way the ScopeUnreadable path names its path and OS error.
    //
    // The live scope deliberately differs from the record in BOTH fields. With matching
    // fixtures a single rendered occurrence would satisfy every assertion below, so a
    // regression that dropped the `scope` side from the format string — or rendered the
    // record's value twice — would still pass.
    let live = Scope {
        boot_id: Some("11111111-2222-3333-4444-555555555555".into()),
        pid_ns: Some(4_026_539_999),
    };
    let e = reject(&linux_record(), &live, RecordErrorKind::ForeignBootSession);
    let rendered = e.to_string();
    assert!(
        rendered.contains("36c39237-f06e-4e88-a74d-ea99d42b817c"),
        "the record's boot id must appear: {rendered}"
    );
    assert!(
        rendered.contains("11111111-2222-3333-4444-555555555555"),
        "and the LIVE boot id it failed to match: {rendered}"
    );
    assert!(
        rendered.contains("4026531836"),
        "the record's pid namespace: {rendered}"
    );
    assert!(rendered.contains("4026539999"), "and the live one: {rendered}");
    assert!(rendered.contains("4242"), "and the pid: {rendered}");
}

#[test]
fn a_scope_read_failure_keeps_the_path_and_the_cause() {
    // The one failure to_record/try_from can have. The mapping is pure, so it is checked
    // on every host even though only Linux can trigger it for real.
    let e = scope_error(ScopeReadError {
        path: "/proc/sys/kernel/random/boot_id".to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "No such file or directory"),
    });
    let Error::IdentityRecord { kind, detail, source } = &e else {
        panic!("expected Error::IdentityRecord, got {e:?}");
    };
    assert_eq!(*kind, RecordErrorKind::ScopeUnreadable);
    assert!(
        detail.contains("/proc/sys/kernel/random/boot_id"),
        "the failing path must be in the detail, got {detail:?}"
    );
    let source = source.as_ref().expect("the io error must be preserved as the source");
    assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
    // And the rendered message must not just repeat the variant's own text.
    let rendered = e.to_string();
    assert!(rendered.contains("/proc/sys/kernel/random/boot_id"), "{rendered}");
}

// Live round trip ======================================================================

use super::{record_from, restore};
use crate::identity::{Existence, Liveness, ProcessId};

/// A scope read that failed, for driving the failure wiring of `record_from` / `restore`.
fn a_failed_scope_read() -> Result<Scope, ScopeReadError> {
    Err(ScopeReadError {
        path: "/proc/sys/kernel/random/boot_id".to_owned(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"),
    })
}

#[test]
fn a_failed_scope_read_aborts_writing_a_record() {
    // Drives the `?` inside `record_from` — the wiring `to_record` is one line of. Runs on
    // every host, including the two whose real `session_scope` cannot fail.
    let e = record_from(&ProcessId::current(), a_failed_scope_read()).expect_err("must not produce a record");
    let Error::IdentityRecord { kind, source, .. } = &e else {
        panic!("expected Error::IdentityRecord, got {e:?}");
    };
    assert_eq!(*kind, RecordErrorKind::ScopeUnreadable);
    assert_eq!(
        source.as_ref().expect("cause preserved").kind(),
        std::io::ErrorKind::PermissionDenied
    );
}

#[test]
fn a_failed_scope_read_aborts_restoring_a_record() {
    // The same for `restore`. The record itself is perfectly valid — only the host's own
    // scope read failed — so anything other than ScopeUnreadable means the `?` is misplaced
    // and a record was validated against a scope nobody managed to read.
    let record = ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::current(),
        pid: 4242,
        token: 1,
        boot_id: None,
        pid_ns: None,
    };
    let e = restore(&record, &Platform::current(), a_failed_scope_read()).expect_err("must not restore");
    let Error::IdentityRecord { kind, .. } = &e else {
        panic!("expected Error::IdentityRecord, got {e:?}");
    };
    assert_eq!(*kind, RecordErrorKind::ScopeUnreadable);
}

#[test]
fn the_current_identity_round_trips_through_a_record() {
    let me = ProcessId::current();
    let record = me.to_record().expect("this host can describe its own boot session");
    assert_eq!(record.version, RECORD_VERSION);
    assert_eq!(record.platform, Platform::current());
    assert_eq!(record.pid, me.pid());
    let back = ProcessId::try_from(&record).expect("a record just written here must restore");
    assert_eq!(back, me, "the restored identity must equal the original");
    // And the restored identity is still a working identity, not just equal bits.
    assert_eq!(back.exists(), Existence::Present);
    assert_eq!(back.is_alive(), Liveness::Alive);
}

#[test]
fn restoring_is_not_a_liveness_check() {
    // A record for a process that has exited still RESTORES — validation is about whether
    // the token can be compared here at all, not about whether the process is there.
    let mut child = crate::test_child::spawn_a_process_that_exits();
    let id = ProcessId::of(child.id())
        .found()
        .expect("a just-spawned child resolves");
    let record = id.to_record().expect("to_record");
    child.wait().expect("wait");
    let back = ProcessId::try_from(&record).expect("a record for a dead process still restores");
    assert_eq!(back, id);
    // `is_alive`, not `exists`: `child` still holds the process handle, and on Windows
    // that pins the kernel object so `exists()` stays Present. `is_alive` reads the
    // signaled state and is correct the instant the process exits.
    assert_eq!(
        back.is_alive(),
        Liveness::Dead,
        "…and only then does it report the process is not running"
    );
}

#[test]
fn a_record_from_this_host_carries_exactly_this_hosts_scope() {
    let record = ProcessId::current().to_record().expect("to_record");
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        // Expected values read INDEPENDENTLY from /proc, not from the new code.
        let boot_id =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").expect("/proc/sys/kernel/random/boot_id");
        assert_eq!(record.boot_id.as_deref(), Some(boot_id.trim()));
        let ino = std::fs::metadata("/proc/self/ns/pid").expect("ns/pid").ino();
        assert_eq!(record.pid_ns, Some(ino));
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(record.boot_id, None, "an absolute token needs no boot session");
        assert_eq!(record.pid_ns, None, "no pid namespaces on this platform");
    }
}

/// Assert `TryFrom` on `record` fails with `kind`.
fn assert_refused(record: &ProcessIdRecord, kind: RecordErrorKind) {
    match ProcessId::try_from(record) {
        Err(Error::IdentityRecord { kind: got, .. }) => assert_eq!(got, kind),
        Err(other) => panic!("expected Error::IdentityRecord({kind:?}), got {other:?}"),
        Ok(id) => panic!("expected {kind:?}, but the record restored to {id:?}"),
    }
}

#[test]
fn a_foreign_platform_record_is_refused_with_a_typed_error() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.platform = Platform::Other("freebsd".into());
    assert_refused(&record, RecordErrorKind::ForeignPlatform);
}

#[test]
fn a_pid_zero_record_is_refused_through_the_live_path() {
    // The path that matters: a corrupt or hand-edited file reaching `Process::kill` with
    // pid 0 would panic in `src/wait/linux.rs` rather than return an error.
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.pid = 0;
    assert_refused(&record, RecordErrorKind::InvalidPid);
}

#[cfg(unix)]
#[test]
fn a_pid_above_i32_max_is_refused_through_the_live_path() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.pid = u32::MAX;
    assert_refused(&record, RecordErrorKind::InvalidPid);
}

// These four run only on Linux because only Linux has a non-empty scope. They are what
// pins `session_scope()` to the shape `validate` compares against: without them a scope
// left empty, or a boot_id read with a trailing newline, would pass every other test while
// silently disabling the boot check (or rejecting every real restore).

#[cfg(target_os = "linux")]
#[test]
fn a_record_from_a_different_boot_is_refused_through_the_live_path() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.boot_id = Some("00000000-0000-0000-0000-000000000000".into());
    assert_refused(&record, RecordErrorKind::ForeignBootSession);
}

#[cfg(target_os = "linux")]
#[test]
fn a_record_without_a_boot_id_is_refused_through_the_live_path() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.boot_id = None;
    assert_refused(&record, RecordErrorKind::MissingBootSession);
}

#[cfg(target_os = "linux")]
#[test]
fn a_record_from_a_different_pid_namespace_is_refused_through_the_live_path() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.pid_ns = Some(record.pid_ns.expect("linux records carry a pid namespace") + 1);
    assert_refused(&record, RecordErrorKind::ForeignPidNamespace);
}

#[cfg(target_os = "linux")]
#[test]
fn a_record_without_a_pid_namespace_is_refused_through_the_live_path() {
    let mut record = ProcessId::current().to_record().expect("to_record");
    record.pid_ns = None;
    assert_refused(&record, RecordErrorKind::MissingPidNamespace);
}

#[cfg(target_os = "linux")]
#[test]
fn an_unreadable_boot_session_is_reported_with_its_path_and_cause() {
    // A real failed read of real paths that do not exist — no mocking. This is the only
    // way ScopeUnreadable is reachable in a test; on Windows and macOS the scope read
    // cannot fail at all, and the pure mapping is covered by
    // `a_scope_read_failure_keeps_the_path_and_the_cause`.
    let missing = std::path::Path::new("/proc/cosca-no-such-boot-id");
    let err = crate::identity::backend::session_scope_at(missing, std::path::Path::new("/proc/self/ns/pid"))
        .map_err(scope_error)
        .expect_err("a nonexistent path must fail");
    let Error::IdentityRecord { kind, detail, source } = &err else {
        panic!("expected Error::IdentityRecord, got {err:?}");
    };
    assert_eq!(*kind, RecordErrorKind::ScopeUnreadable);
    assert!(detail.contains("/proc/cosca-no-such-boot-id"), "{detail}");
    assert_eq!(
        source.as_ref().expect("cause preserved").kind(),
        std::io::ErrorKind::NotFound
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_blank_boot_id_is_refused_rather_than_stored() {
    // A container runtime that masks the boot_id file (bind-mounting /dev/null over it)
    // makes the read SUCCEED and return "". Storing that as Some("") would compare equal to
    // the next boot's Some(""), silently disabling the boot-session check. A real file, a
    // real read — the emptiness is genuine, not mocked.
    let dir = tempfile::tempdir().expect("tempdir");
    let blank = dir.path().join("boot_id");
    std::fs::write(&blank, "\n").expect("write");
    let err = crate::identity::backend::session_scope_at(&blank, std::path::Path::new("/proc/self/ns/pid"))
        .map_err(scope_error)
        .expect_err("a blank boot_id must be refused");
    let Error::IdentityRecord { kind, .. } = &err else {
        panic!("expected Error::IdentityRecord, got {err:?}");
    };
    assert_eq!(*kind, RecordErrorKind::ScopeUnreadable);
}
