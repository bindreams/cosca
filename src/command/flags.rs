//! The creation-flag request a caller records on a [`Command`](crate::Command), and the one
//! function that turns it into the `dwCreationFlags` word cosca supplies to a Windows spawn.
//!
//! # What the composed word is, and is not
//!
//! [`windows_spawn`] returns **what cosca supplies** for a given backend — never what
//! `CreateProcessW` receives. On the std backend those differ: std stores the word verbatim and
//! then ORs `CREATE_UNICODE_ENVIRONMENT` into it at spawn, plus `EXTENDED_STARTUPINFO_PRESENT`
//! when it holds a proc-thread attribute list. No predicate may read the returned word as a fact
//! about the child, with one argued exception: `mechanism_from_flags` reads only four bits that
//! std neither adds nor removes.
//!
//! # What the flags settle about the child's console
//!
//! Measured on Windows 11: a plain console-subsystem child joins the spawner's console;
//! `CREATE_NO_WINDOW` gives it a *windowless console of its own*; `DETACHED_PROCESS` gives it
//! none; `CREATE_NEW_CONSOLE` gives it a visible one, overriding a requested suppression.
//!
//! The reading is **one-directional**. A suppressing or detaching flag being present is enough
//! to know the child is not in this process's console. The converse is false: the image's
//! subsystem decides console membership too — a windows-subsystem image never attaches to its
//! spawner's console whatever the word says — and a child may free or reallocate its own console
//! after it starts. Nothing here describes whether a signal would be *delivered*; that is not
//! knowable from inside this process.

#[cfg(windows)]
use crate::containment::ContainRequest;
#[cfg(windows)]
use crate::error::Error;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CREATE_BREAKAWAY_FROM_JOB, CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, DEBUG_ONLY_THIS_PROCESS, DEBUG_PROCESS, DETACHED_PROCESS, EXTENDED_STARTUPINFO_PRESENT,
};

/// What a caller asked for, recorded on the builder and validated at spawn.
///
/// Validation is deliberately not in the setters: a pairwise rule enforced there would give a
/// verdict that depends on builder call order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FlagsRequest {
    /// "Do not put a console window on the user's screen" — the one portable intent. Lowered to
    /// a creation flag on the ordinary Windows backends, to a show-command on the consent-prompt
    /// elevation launch, and to nothing at all on Unix.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub no_window: bool,
    #[cfg(windows)]
    pub detached: bool,
    #[cfg(windows)]
    pub breakaway_from_job: bool,
    /// The raw hatch. `0` is indistinguishable from never calling `creation_flags`, which is
    /// correct: a zero word requests no bits, so there is nothing to refuse and nothing to emit.
    #[cfg(windows)]
    pub raw: u32,
}

/// Which Windows spawn mechanism the word is being composed for. The raw `CreateProcessW`
/// backend needs two structural bits it cannot spawn without; std supplies its own.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpawnBackend {
    Std,
    Raw,
}

/// Everything cosca decided about a Windows spawn before it happens.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct WindowsSpawn {
    /// The complete word cosca supplies to the backend — see the module doc for why that is not
    /// the word the OS receives.
    pub creation_flags: u32,
    /// Whether this spawn must set the inherited root marker so descendants join THIS group.
    /// Read by the raw backends, which build their own environment block; the std path applies
    /// the marker through the portable path `prepare` shares with Unix.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub marker_env: bool,
}

/// A bit `creation_flags` refuses, and what to reach for instead.
#[cfg(windows)]
struct Reserved {
    bit: u32,
    name: &'static str,
    remedy: &'static str,
}

/// The reserved set, in ascending bit order so a multi-bit refusal reads in a stable sequence.
#[cfg(windows)]
fn reserved_table() -> [Reserved; 10] {
    [
        Reserved {
            bit: DEBUG_PROCESS.0,
            name: "DEBUG_PROCESS",
            remedy: "no replacement: it makes the spawner a debugger, and the child stops on debug \
                     events nothing here services, so wait()/wait_tree() would hang",
        },
        Reserved {
            bit: DEBUG_ONLY_THIS_PROCESS.0,
            name: "DEBUG_ONLY_THIS_PROCESS",
            remedy: "no replacement: same reason as DEBUG_PROCESS",
        },
        Reserved {
            bit: CREATE_SUSPENDED.0,
            name: "CREATE_SUSPENDED",
            remedy: "no replacement yet: cosca suspends and resumes a contained root itself, so a \
                     caller's suspend would be resumed silently on a contained spawn and never \
                     resumed at all on an uncontained one",
        },
        Reserved {
            bit: DETACHED_PROCESS.0,
            name: "DETACHED_PROCESS",
            remedy: "use detached()",
        },
        Reserved {
            bit: CREATE_NEW_CONSOLE.0,
            name: "CREATE_NEW_CONSOLE",
            remedy: "no replacement: measured to give the child its own VISIBLE console window, \
                     overriding a requested window suppression",
        },
        Reserved {
            bit: CREATE_NEW_PROCESS_GROUP.0,
            name: "CREATE_NEW_PROCESS_GROUP",
            remedy: "use contain(), which is what makes the child's group addressable",
        },
        Reserved {
            bit: CREATE_UNICODE_ENVIRONMENT.0,
            name: "CREATE_UNICODE_ENVIRONMENT",
            remedy: "no replacement: both backends supply it structurally — the raw one always \
                     builds a UTF-16 environment block, and std ORs the bit in regardless of what \
                     it was given",
        },
        Reserved {
            bit: EXTENDED_STARTUPINFO_PRESENT.0,
            name: "EXTENDED_STARTUPINFO_PRESENT",
            remedy: "no replacement: it announces a structure only the spawn backend can supply",
        },
        Reserved {
            bit: CREATE_BREAKAWAY_FROM_JOB.0,
            name: "CREATE_BREAKAWAY_FROM_JOB",
            remedy: "use breakaway_from_job(), which also classifies the failure a forbidding \
                     ambient job produces",
        },
        Reserved {
            bit: CREATE_NO_WINDOW.0,
            name: "CREATE_NO_WINDOW",
            remedy: "use no_window()",
        },
    ]
}

/// The reserved bits present in `raw`, in ascending bit order.
#[cfg(windows)]
fn reserved_bits_in(raw: u32) -> Vec<Reserved> {
    let mut hits: Vec<Reserved> = reserved_table().into_iter().filter(|r| raw & r.bit != 0).collect();
    hits.sort_by_key(|r| r.bit);
    hits
}

/// Compose the `dwCreationFlags` word cosca supplies to `backend` for this spawn, and refuse the
/// combinations cosca cannot honour.
///
/// Pure: `contain`, `flags` and `is_root` are all recorded state, so the verdict never depends on
/// process state that could change between the reading and the spawn. Every rule that *does* need
/// to know about the ambient job is a post-failure classifier instead.
#[cfg(windows)]
pub(crate) fn windows_spawn(
    contain: &ContainRequest,
    flags: FlagsRequest,
    is_root: bool,
    backend: SpawnBackend,
) -> Result<WindowsSpawn, Error> {
    let offending = reserved_bits_in(flags.raw);
    if !offending.is_empty() {
        let named = offending
            .iter()
            .map(|r| format!("{} ({})", r.name, r.remedy))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::Unsupported {
            op: "creation_flags".into(),
            platform: "windows",
            detail: format!("creation flags cosca manages itself cannot be set through the raw hatch: {named}"),
        });
    }

    // Pure, so there is no staleness to race: both operands are recorded on the builder. For a
    // NESTED contained spawn cosca's containment IS "the child inherits the ancestor's job", and
    // breaking away leaves it while `Containment::Delegated` still claims the root will tear it
    // down — a report that is simply false. A root contained spawn is arguably safe, but making
    // the verdict depend on root-ness would mean the identical `Command` succeeds in one process
    // and fails in a nested one.
    if flags.breakaway_from_job && contain.mode.is_some() {
        return Err(Error::Unsupported {
            op: "breakaway_from_job() with contain()".into(),
            platform: "windows",
            detail: "cosca's containment is a job object the child must be inside for the tree                      teardown it reports to be true, and a nested contained spawn's containment IS                      inheriting the ancestor's job. Drop one of the two."
                .into(),
        });
    }

    let setup = crate::containment::dispatch::windows_contain_setup(contain, is_root);
    let mut creation_flags = setup.creation_flags | flags.raw;
    if flags.no_window {
        creation_flags |= CREATE_NO_WINDOW.0;
    }
    if flags.detached {
        creation_flags |= DETACHED_PROCESS.0;
    }
    // Emitted from the request alone. The flag is a documented no-op when this process is in no
    // job, so omitting it on a "not in a job" reading buys nothing and costs the caller's request
    // if the reading goes stale before the spawn.
    if flags.breakaway_from_job {
        creation_flags |= CREATE_BREAKAWAY_FROM_JOB.0;
    }
    if backend == SpawnBackend::Raw {
        creation_flags |= CREATE_UNICODE_ENVIRONMENT.0 | EXTENDED_STARTUPINFO_PRESENT.0;
    }
    Ok(WindowsSpawn {
        creation_flags,
        marker_env: setup.marker_env,
    })
}

/// Classify a Windows spawn-syscall failure. Pure — the OS's error and the ambient job's verdict
/// are both parameters — so every arm is unit-testable without the OS producing the configuration.
///
/// It runs on the error path of a spawn SYSCALL and nowhere else. Everything above a syscall
/// (stdio resolution, executable resolution, handle-inherit calls, the attribute list, the
/// post-spawn attach) can fail access-denied for reasons that have nothing to do with a breakaway
/// request, and the soundness argument below holds only for the error the spawn call itself
/// returned.
///
/// **Why naming the request is sound.** With a forbidding ambient job, an emitted
/// `CREATE_BREAKAWAY_FROM_JOB` *guarantees* an access-denied failure, so the request is a
/// sufficient cause of the failure the caller just got — honest even if the image's own ACL would
/// also have denied the spawn, since fixing the named cause is necessary either way.
///
/// **Why the message claims only FIRST.** Measured: the breakaway denial is evaluated before the
/// image is resolved — a spawn of a path that does not exist, inside a forbidding job, fails
/// access-denied rather than file-not-found. So a genuine "no such program" is masked, and the
/// detail says what was measured and stops there.
///
/// Two error encodings reach here and both are accepted: the std path returns the bare Win32
/// code, while the raw backends convert a `windows::core::Error` whose `raw_os_error` is the
/// HRESULT.
#[cfg(windows)]
pub(crate) fn classify_spawn_denial(
    err: Error,
    flags: FlagsRequest,
    job: crate::containment::windows::JobBreakaway,
) -> Error {
    use crate::containment::windows::JobBreakaway;
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

    if !flags.breakaway_from_job {
        return err;
    }
    let Error::Io(io) = &err else {
        return err;
    };
    let win32 = ERROR_ACCESS_DENIED.0 as i32;
    let hresult = windows::core::HRESULT::from_win32(ERROR_ACCESS_DENIED.0).0;
    if !matches!(io.raw_os_error(), Some(c) if c == win32 || c == hresult) {
        return err;
    }
    // Never assert a cause the process just measured to be false, or could not measure at all.
    if job != JobBreakaway::Forbidden {
        return err;
    }
    Error::Containment {
        detail: "the spawn was refused with ACCESS_DENIED, and this process's job object sets                  neither JOB_OBJECT_LIMIT_BREAKAWAY_OK nor JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,                  so it forbids the breakaway_from_job() this spawn requested. Windows evaluates                  that check before it resolves the image, so this is the FIRST thing refused and                  not necessarily the only problem: dropping the request may reveal a different                  failure rather than making the spawn work. Only whoever created that job can                  permit breakaway — and if this process was itself spawned by cosca with                  contain(), the job is cosca's own, which sets neither limit and whose limits a                  member process cannot relax."
            .into(),
    }
}

/// The one impure adapter, called at the Windows spawn syscalls and nowhere else, so no spawn
/// path grows a probe call of its own.
///
/// The probe therefore runs on every failed Windows spawn syscall, not only breakaway ones. That
/// is deliberate: two syscalls on an already-failing spawn are irrelevant, and gating the probe
/// would move part of the decision out of the pure function above and into untested glue.
#[cfg(windows)]
pub(crate) fn classify_spawn_syscall_error(err: Error, flags: FlagsRequest) -> Error {
    classify_spawn_denial(err, flags, crate::containment::windows::probe_job_breakaway())
}

#[cfg(all(test, windows))]
#[path = "flags_tests.rs"]
mod flags_tests;
