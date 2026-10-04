use std::cell::Cell;
use std::io;

use super::{gate, Gate};
use crate::elevation::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

const PID: u32 = 4242;

const FRONTS: [(ElevatedVia, &str); 3] = [
    (ElevatedVia::Wrapped(Backend::Sudo), "sudo"),
    (ElevatedVia::Wrapped(Backend::Doas), "doas"),
    (ElevatedVia::MacosOsascript, "osascript"),
];

/// Runs `gate`, counting how often it asked whether the front is running.
fn gate_counting(via: Option<&ElevatedVia>, cgroup: bool, running: io::Result<bool>) -> (Gate, u32) {
    let asked = Cell::new(0);
    let mut running = Some(running);
    let g = gate(via, PID, cgroup, || {
        asked.set(asked.get() + 1);
        running.take().expect("asked once")
    });
    (g, asked.get())
}

fn unkillable_detail(g: Gate) -> String {
    match g {
        Gate::Closed(Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
        }) => detail,
        other => panic!("expected a closed gate with Unkillable, got {other:?}"),
    }
}

/// Mutants: a front is signalled (`Open`); the front check is skipped; the detail names neither.
#[skuld::test]
fn a_live_uncontained_front_is_closed_with_unkillable_naming_it() {
    for (via, name) in FRONTS {
        let (g, asked) = gate_counting(Some(&via), false, Ok(true));
        assert_eq!(asked, 1, "{via:?}");
        let detail = unkillable_detail(g);
        assert!(detail.contains(&format!("pid {PID} is {name}")), "{detail}");
        assert!(detail.contains("nothing was sent"), "{detail}");
    }
}

/// An exited front has nothing left to orphan: a kill of it answers as any child's does, in a
/// cgroup too. Mutants: the exit is ignored, so a kill after the program finished is `Unkillable`;
/// a cgroup kill runs for a front that has exited.
#[skuld::test]
fn an_exited_front_is_open() {
    for (via, _) in FRONTS {
        for cgroup in [false, true] {
            let (g, asked) = gate_counting(Some(&via), cgroup, Ok(false));
            assert_eq!(asked, 1, "{via:?}");
            assert!(matches!(g, Gate::Open), "{via:?} cgroup={cgroup}: {g:?}");
        }
    }
}

/// A front whose state cannot be read is treated as live, and the reason is kept. Mutant: an
/// unreadable state opens the gate.
#[skuld::test]
fn a_front_whose_state_cannot_be_read_is_closed_and_says_why() {
    let (g, _) = gate_counting(
        Some(&ElevatedVia::Wrapped(Backend::Sudo)),
        false,
        Err(io::Error::other("peek refused")),
    );
    let detail = unkillable_detail(g);
    assert!(detail.contains("could not be read: peek refused"), "{detail}");
}

/// A cgroup kill reaches the program whatever its credentials, so a live front, or one whose
/// state cannot be read, is killed through it. Mutant: a contained front is closed too.
#[skuld::test]
fn a_live_front_in_a_cgroup_is_killed_through_the_cgroup_first() {
    for (via, _) in FRONTS {
        for running in [Ok(true), Err(io::Error::other("peek refused"))] {
            let (g, asked) = gate_counting(Some(&via), true, running);
            assert_eq!(asked, 1, "{via:?}");
            assert!(matches!(g, Gate::CgroupFirst), "{via:?}: {g:?}");
        }
    }
}

/// The tracked process is the program itself, or there is no elevation: signalled like any child,
/// with no state read. Mutant: pkexec or UAC counted as a front.
#[skuld::test]
fn a_child_that_is_not_a_front_is_open_whatever_its_containment() {
    let not_fronts = [
        None,
        Some(ElevatedVia::Wrapped(Backend::Pkexec)),
        Some(ElevatedVia::Wrapped(Backend::Run0)),
        Some(ElevatedVia::WindowsUac),
        Some(ElevatedVia::AlreadyElevated),
    ];
    for via in &not_fronts {
        for cgroup in [false, true] {
            let (g, asked) = gate_counting(via.as_ref(), cgroup, Ok(true));
            assert_eq!(asked, 0, "{via:?}");
            assert!(matches!(g, Gate::Open), "{via:?} cgroup={cgroup}: {g:?}");
        }
    }
}
