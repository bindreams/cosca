use std::cell::Cell;
use std::io;

use super::{front, kill_gate, terminate_gate, Gate};
use crate::elevation::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

const PID: u32 = 4242;

const FRONTS: [(ElevatedVia, &str); 3] = [
    (ElevatedVia::Wrapped(Backend::Sudo), "sudo"),
    (ElevatedVia::Wrapped(Backend::Doas), "doas"),
    (ElevatedVia::MacosOsascript, "osascript"),
];

const NOT_FRONTS: [Option<ElevatedVia>; 4] = [
    None,
    Some(ElevatedVia::Wrapped(Backend::Pkexec)),
    Some(ElevatedVia::WindowsUac),
    Some(ElevatedVia::AlreadyElevated),
];

/// The kill gate for `via`, outside a cgroup or in one, and whether it asked if the front runs.
fn kill_gate_asking(via: Option<&ElevatedVia>, in_cgroup: bool, running: io::Result<bool>) -> (Gate, bool) {
    let asked = Cell::new(false);
    let g = kill_gate(front(via), PID, in_cgroup, || {
        asked.set(true);
        running
    });
    (g, asked.get())
}

fn refusal_detail(g: Gate) -> String {
    match g {
        Gate::Closed(Error::Elevation {
            kind: ElevationErrorKind::Unkillable,
            detail,
        }) => detail,
        other => panic!("expected a closed gate with Unkillable, got {other:?}"),
    }
}

#[skuld::test]
fn a_live_front_outside_a_cgroup_is_closed_with_unkillable_naming_it() {
    for (via, name) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(&via), false, Ok(true));
        assert!(asked, "{via:?}");
        let detail = refusal_detail(g);
        assert!(detail.contains(&format!("pid {PID} is")), "{detail}");
        assert!(detail.contains(name), "{detail}");
        assert!(detail.contains("no kill was sent"), "{detail}");
        assert_eq!(
            detail.contains("direct exec"),
            name != "osascript",
            "only a wrapper may track the program itself: {detail}"
        );
    }
}

/// An exited front has nothing of its own left to kill.
#[skuld::test]
fn an_exited_front_is_exited() {
    for (via, _) in FRONTS {
        let (g, _) = kill_gate_asking(Some(&via), false, Ok(false));
        assert!(matches!(g, Gate::Exited), "{via:?}: {g:?}");
    }
}

/// A child contained in a cgroup is not gated, and nothing is read about it.
#[skuld::test]
fn a_front_in_a_cgroup_is_open() {
    for (via, _) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(&via), true, Ok(true));
        assert!(!asked, "{via:?}");
        assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
    }
}

/// A front whose state cannot be read is closed, and says why.
#[skuld::test]
fn a_front_whose_state_cannot_be_read_is_closed_and_says_why() {
    let sudo = ElevatedVia::Wrapped(Backend::Sudo);
    let (g, _) = kill_gate_asking(Some(&sudo), false, Err(io::Error::other("peek refused")));
    assert!(refusal_detail(g).contains("could not be read: peek refused"));
}

/// The tracked process is the program itself, or there is no elevation: signalled like any child,
/// with nothing read.
#[skuld::test]
fn a_child_that_is_not_a_front_is_open_whatever_its_containment() {
    for via in &NOT_FRONTS {
        for in_cgroup in [false, true] {
            let (g, asked) = kill_gate_asking(via.as_ref(), in_cgroup, Ok(true));
            assert!(!asked, "{via:?}");
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
            let g = terminate_gate(front(via.as_ref()), PID, || panic!("not asked"));
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
        }
    }
}

/// sudo and doas relay `SIGTERM` to the program: never gated.
#[skuld::test]
fn a_sigterm_to_a_relaying_front_is_open() {
    for via in [ElevatedVia::Wrapped(Backend::Sudo), ElevatedVia::Wrapped(Backend::Doas)] {
        let g = terminate_gate(front(Some(&via)), PID, || panic!("not asked"));
        assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
    }
}

/// A `SIGTERM` would end osascript and orphan the program: refused while osascript runs, sent once
/// it has exited.
#[skuld::test]
fn a_sigterm_to_a_live_osascript_is_closed() {
    let osascript = ElevatedVia::MacosOsascript;
    let detail = refusal_detail(terminate_gate(front(Some(&osascript)), PID, || Ok(true)));
    assert!(detail.contains(&format!("pid {PID} is osascript")), "{detail}");
    assert!(detail.contains("no SIGTERM was sent"), "{detail}");
    let detail = refusal_detail(terminate_gate(front(Some(&osascript)), PID, || {
        Err(io::Error::other("peek refused"))
    }));
    assert!(detail.contains("peek refused"), "{detail}");
    assert!(matches!(
        terminate_gate(front(Some(&osascript)), PID, || Ok(false)),
        Gate::Open
    ));
}
