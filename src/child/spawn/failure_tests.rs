use super::{Classify, SpawnFailure};
use crate::error::{ChildFate, Error};

// Compile-fail shape, see the `failure` module doc.
static_assertions::assert_not_impl_any!(SpawnFailure: From<Error>, From<std::io::Error>);
static_assertions::assert_not_impl_any!(Result<(), SpawnFailure>: Classify<()>);
static_assertions::assert_impl_all!(Result<(), Error>: Classify<()>);
static_assertions::assert_impl_all!(Result<(), std::io::Error>: Classify<()>);

fn io(what: &str) -> Error {
    Error::Io(std::io::Error::other(what.to_string()))
}

/// Mutant: `From<SpawnFailure>` drops the answer, or the fate, of a may-have-started failure.
#[skuld::test]
fn a_may_have_started_failure_becomes_the_wrapping_variant() {
    let fate = ChildFate::Running {
        id: Some(crate::identity::ProcessId::current()),
    };
    let error = Error::from(SpawnFailure::started(io("attach"), fate));
    let Error::MayHaveStarted { fate: got, source, .. } = &error else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(*got, fate);
    assert!(
        matches!(**source, Error::Io(ref e) if e.to_string() == "attach"),
        "{source:?}"
    );
    assert_eq!(error.fate(), Some(fate), "`fate` reads the wrapping variant");
    assert_eq!(
        Error::Io(std::io::Error::other("x")).fate(),
        None,
        "any other variant did not start"
    );
    let text = error.to_string();
    let pid = std::process::id();
    assert!(
        text.contains("may have started") && text.contains(&format!("pid {pid}")),
        "{text}"
    );
    assert!(
        std::error::Error::source(&error).is_some_and(|s| s.to_string() == "attach"),
        "the cause is the source"
    );
}

/// Mutant: `From<SpawnFailure>` wraps a not-started failure.
#[skuld::test]
fn a_not_started_failure_is_its_cause_unchanged() {
    let error = Error::from(SpawnFailure::NotStarted(io("exec")));
    assert!(
        matches!(error, Error::Io(ref e) if e.to_string() == "exec"),
        "{error:?}"
    );
}

/// A cause that is itself a `MayHaveStarted` is a contract breach, and asserts in debug.
///
/// Mutant: `From<SpawnFailure>` wraps it again, or passes it through, without the assertion.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "is itself `may have started`"))]
fn a_cause_that_is_itself_may_have_started_asserts() {
    let once = Error::from(SpawnFailure::started(io("identity"), ChildFate::Reaped));
    drop(Error::from(SpawnFailure::started(once, ChildFate::Unknown)));
}

/// `behind_wrapper` only sets the flag: the cause and fate stand, and a not-started failure is
/// unchanged.
///
/// Mutant: `behind_wrapper` drops the flag, changes the fate, or marks a not-started failure.
#[skuld::test]
fn behind_wrapper_sets_the_flag_alone() {
    let marked = Error::from(SpawnFailure::started(io("attach"), ChildFate::Killed).behind_wrapper());
    let Error::MayHaveStarted {
        fate,
        wrapper_elevated,
        source,
        ..
    } = &marked
    else {
        panic!("expected MayHaveStarted, got {marked:?}");
    };
    assert_eq!(*fate, ChildFate::Killed);
    assert!(*wrapper_elevated);
    assert!(
        matches!(**source, Error::Io(ref e) if e.to_string() == "attach"),
        "{source:?}"
    );
    let plain = Error::from(SpawnFailure::started(io("attach"), ChildFate::Killed));
    assert!(
        matches!(
            plain,
            Error::MayHaveStarted {
                wrapper_elevated: false,
                ..
            }
        ),
        "{plain:?}"
    );
    let not = Error::from(SpawnFailure::NotStarted(io("exec")).behind_wrapper());
    assert!(matches!(not, Error::Io(_)), "{not:?}");
}

/// A run-to-completion helper's failure after its spawn carries the cause, the fate and the
/// wrapper flag: the flag survives for every cause, `read`'s invalid UTF-8 included.
///
/// Mutant: `after_the_spawn` drops the flag.
#[skuld::test]
fn after_the_spawn_keeps_the_cause_the_fate_and_the_wrapper_flag() {
    for wrapper in [false, true] {
        let error = super::after_the_spawn(io("wait"), ChildFate::Reaped, wrapper);
        let Error::MayHaveStarted {
            fate,
            wrapper_elevated,
            source,
            ..
        } = &error
        else {
            panic!("expected MayHaveStarted, got {error:?}");
        };
        assert_eq!(*fate, ChildFate::Reaped);
        assert_eq!(*wrapper_elevated, wrapper);
        assert!(
            matches!(**source, Error::Io(ref e) if e.to_string() == "wait"),
            "{source:?}"
        );
    }
}

/// A child over a fake that has exited, so dropping it waits for nothing.
fn unreaped_child(id: crate::identity::ProcessId) -> Box<crate::child::Unreaped> {
    use crate::os_process::child::ExitRecord;
    use crate::os_process::fake::{FakeProcess, ReapAnswer};

    let exit = ExitRecord::Status(std::process::ExitStatus::default());
    let fake = FakeProcess::new([])
        .with_pid(id.pid())
        .reaps([ReapAnswer::Reaped(exit)]);
    let child = crate::child::owned::OwnedChild::new(Box::new(fake));
    Box::new(crate::child::Unreaped::new(child, Some(id)))
}

/// A failure that carries a child keeps it through `map`, `behind_wrapper` and the conversion to
/// an `Error`; a failure built by `started` carries none.
///
/// Mutants: any of the three drops `unreaped`; `started` invents one.
#[skuld::test]
fn a_failure_carries_its_unreaped_child_through_map_behind_wrapper_and_from() {
    let id = crate::identity::ProcessId::current();
    let failure = SpawnFailure::MayHaveStarted {
        cause: io("attach"),
        fate: ChildFate::Running { id: Some(id) },
        wrapper_elevated: false,
        unreaped: Some(unreaped_child(id)),
    };
    let error = Error::from(failure.map(|_| io("mapped")).behind_wrapper());
    let Error::MayHaveStarted {
        unreaped: Some(child),
        wrapper_elevated: true,
        ..
    } = error
    else {
        panic!("expected MayHaveStarted around a child, got {error:?}");
    };
    assert_eq!(child.pid(), Some(id.pid()));
    let none = Error::from(SpawnFailure::started(io("attach"), ChildFate::Reaped));
    assert!(matches!(none, Error::MayHaveStarted { unreaped: None, .. }), "{none:?}");
}

/// A child is handed back only with the fate `Running` and its own identity: anything else is a
/// contract breach, and asserts in debug.
///
/// Mutant: `From` does not check the fate against the child.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "is `Running` with its identity"))]
fn an_unreaped_child_whose_fate_is_not_running_asserts_in_debug() {
    let id = crate::identity::ProcessId::current();
    drop(Error::from(SpawnFailure::MayHaveStarted {
        cause: io("attach"),
        fate: ChildFate::Reaped,
        wrapper_elevated: false,
        unreaped: Some(unreaped_child(id)),
    }));
}

/// As above, for a `Running` fate that names another identity (or none).
///
/// Mutant: `From` checks the variant of the fate and not its identity.
#[skuld::test]
#[cfg_attr(debug_assertions, should_panic(expected = "is `Running` with its identity"))]
fn an_unreaped_child_whose_fate_names_another_identity_asserts_in_debug() {
    let id = crate::identity::ProcessId::current();
    drop(Error::from(SpawnFailure::MayHaveStarted {
        cause: io("attach"),
        fate: ChildFate::Running { id: None },
        wrapper_elevated: false,
        unreaped: Some(unreaped_child(id)),
    }));
}

#[skuld::test]
fn classify_names_not_started() {
    let not: Result<(), _> = Err::<(), _>(std::io::Error::other("pipe")).not_started();
    assert!(matches!(not, Err(SpawnFailure::NotStarted(Error::Io(_)))), "{not:?}");
}

#[skuld::test]
fn map_keeps_the_answer_the_fate_and_the_flag() {
    let mapped = SpawnFailure::started(io("a"), ChildFate::Killed)
        .behind_wrapper()
        .map(|_| io("b"));
    assert!(
        matches!(
            mapped,
            SpawnFailure::MayHaveStarted {
                cause: Error::Io(ref e),
                fate: ChildFate::Killed,
                wrapper_elevated: true,
                ..
            } if e.to_string() == "b"
        ),
        "{mapped:?}"
    );
    let mapped = SpawnFailure::NotStarted(io("a")).map(|_| io("b"));
    assert!(matches!(mapped, SpawnFailure::NotStarted(Error::Io(ref e)) if e.to_string() == "b"));
}

/// A note added to a may-have-started error lands on its cause, which keeps its variant, and the
/// fate is kept.
#[skuld::test]
fn a_note_on_a_may_have_started_error_reaches_its_cause() {
    let error = Error::from(SpawnFailure::started(
        Error::Containment { detail: "x".into() },
        ChildFate::Gone,
    ))
    .with_note("front left");
    let Error::MayHaveStarted { fate, source, .. } = &error else {
        panic!("expected MayHaveStarted, got {error:?}");
    };
    assert_eq!(*fate, ChildFate::Gone);
    assert!(
        matches!(**source, Error::Containment { ref detail } if detail == "x; front left"),
        "{source:?}"
    );
}

/// Each fate reads as what it says.
///
/// Mutant: two fates share a message.
#[skuld::test]
fn each_fate_has_its_own_message() {
    let all = [
        ChildFate::Reaped,
        ChildFate::Killed,
        ChildFate::Running {
            id: Some(crate::identity::ProcessId::current()),
        },
        ChildFate::Running { id: None },
        ChildFate::Gone,
        ChildFate::Unknown,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a.to_string(), b.to_string(), "{a:?} vs {b:?}");
        }
    }
    let running = ChildFate::Running {
        id: Some(crate::identity::ProcessId::current()),
    };
    assert!(running.to_string().contains(&format!("pid {}", std::process::id())));
}

/// A look at a child cosca did not kill: `Gone` only for a child someone else reaped (`ECHILD`),
/// `Running` only for one that has not exited, `Unknown` for any other failure.
///
/// A child still running is `Running` with the identity the caller knows, and none when it knows none.
///
/// Mutant: a failed look is `Running`, `ECHILD` is `Unknown`, or the identity is dropped or invented.
#[cfg(unix)]
#[skuld::test]
fn a_look_at_an_unkilled_child_tells_reaped_running_gone_and_unknown_apart() {
    use std::os::unix::process::ExitStatusExt as _;

    use super::super::fate_of_a_look;
    let exited = std::process::ExitStatus::from_raw(0);
    let id = Some(crate::identity::ProcessId::current());
    assert_eq!(fate_of_a_look(Ok(Some(exited)), id), ChildFate::Reaped);
    assert_eq!(fate_of_a_look(Ok(None), None), ChildFate::Running { id: None });
    assert_eq!(fate_of_a_look(Ok(None), id), ChildFate::Running { id });
    assert_eq!(fate_of_a_look(Err(Some(libc::ECHILD)), id), ChildFate::Gone);
    assert_eq!(fate_of_a_look(Err(Some(libc::EIO)), id), ChildFate::Unknown);
    assert_eq!(fate_of_a_look(Err(None), id), ChildFate::Unknown);
}
