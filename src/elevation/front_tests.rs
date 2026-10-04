use std::cell::Cell;
use std::io;

use super::{kill_gate, terminate_gate, Gate};
use crate::elevation::{Backend, ElevatedVia};
use crate::error::{ElevationErrorKind, Error};

const PID: u32 = 4242;

const FRONTS: [(ElevatedVia, &str); 3] = [
    (ElevatedVia::Wrapped(Backend::Sudo), "sudo"),
    (ElevatedVia::Wrapped(Backend::Doas), "doas"),
    (ElevatedVia::MacosOsascript, "osascript"),
];

const NOT_FRONTS: [Option<ElevatedVia>; 5] = [
    None,
    Some(ElevatedVia::Wrapped(Backend::Pkexec)),
    Some(ElevatedVia::Wrapped(Backend::Run0)),
    Some(ElevatedVia::WindowsUac),
    Some(ElevatedVia::AlreadyElevated),
];

/// What a gate asked, in order: `r` for `running`, `c` for `in_cgroup`.
fn kill_gate_asking(
    via: Option<&ElevatedVia>,
    running: io::Result<bool>,
    in_cgroup: io::Result<bool>,
) -> (Gate, String) {
    let asked = Cell::new(String::new());
    let note = |c: char| {
        let mut s = asked.take();
        s.push(c);
        asked.set(s);
    };
    let g = kill_gate(
        via,
        PID,
        || {
            note('r');
            running
        },
        || {
            note('c');
            in_cgroup
        },
    );
    (g, asked.take())
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

/// Mutants: a front is signalled (`Open`); the detail names neither the pid nor the front; it
/// claims a sudo pid is the wrapper when, with direct exec, it may be the program.
#[skuld::test]
fn a_live_front_outside_a_cgroup_is_closed_with_unkillable_naming_it() {
    for (via, name) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(&via), Ok(true), Ok(false));
        assert_eq!(asked, "rc", "{via:?}");
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

/// A front that has left its cgroup (pam_systemd moving sudo into a session scope) is outside it.
/// Mutant: any front of a cgroup-contained child is killed through the cgroup.
#[skuld::test]
fn a_live_front_that_left_its_cgroup_is_closed() {
    let (g, _) = kill_gate_asking(Some(&ElevatedVia::Wrapped(Backend::Sudo)), Ok(true), Ok(false));
    refusal_detail(g);
}

/// An exited front has nothing left to orphan, and its cgroup is not asked about. Mutants: the
/// exit is ignored; a cgroup kill runs for an exited front.
#[skuld::test]
fn an_exited_front_is_exited() {
    for (via, _) in FRONTS {
        let (g, asked) = kill_gate_asking(Some(&via), Ok(false), Ok(true));
        assert_eq!(asked, "r", "{via:?}");
        assert!(matches!(g, Gate::Exited), "{via:?}: {g:?}");
    }
}

/// A cgroup kill reaches a member whatever its credentials, so a live front in one, or one whose
/// state cannot be read, is killed through it. Mutant: a contained front is closed too.
#[skuld::test]
fn a_live_front_in_its_cgroup_is_killed_through_the_cgroup_only() {
    for (via, _) in FRONTS {
        for running in [Ok(true), Err(io::Error::other("peek refused"))] {
            let (g, asked) = kill_gate_asking(Some(&via), running, Ok(true));
            assert_eq!(asked, "rc", "{via:?}");
            assert!(matches!(g, Gate::CgroupOnly), "{via:?}: {g:?}");
        }
    }
}

/// A front whose state or membership cannot be read is closed, and says why. Mutants: either
/// unreadable answer opens the gate; the reason is dropped.
#[skuld::test]
fn a_front_whose_state_cannot_be_read_is_closed_and_says_why() {
    let sudo = ElevatedVia::Wrapped(Backend::Sudo);
    let (g, _) = kill_gate_asking(Some(&sudo), Err(io::Error::other("peek refused")), Ok(false));
    assert!(refusal_detail(g).contains("could not be read: peek refused"));
    let (g, _) = kill_gate_asking(Some(&sudo), Ok(true), Err(io::Error::other("procs refused")));
    assert!(refusal_detail(g).contains("could not be read: procs refused"));
}

/// The tracked process is the program itself, or there is no elevation: signalled like any child,
/// with nothing read. Mutant: pkexec or UAC counted as a front.
#[skuld::test]
fn a_child_that_is_not_a_front_is_open_whatever_its_containment() {
    for via in &NOT_FRONTS {
        for in_cgroup in [false, true] {
            let (g, asked) = kill_gate_asking(via.as_ref(), Ok(true), Ok(in_cgroup));
            assert_eq!(asked, "", "{via:?}");
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
            let g = terminate_gate(via.as_ref(), PID, || panic!("not asked"));
            assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
        }
    }
}

/// sudo and doas relay `SIGTERM` to the program: never gated. Mutant: every front's `SIGTERM` is
/// refused.
#[skuld::test]
fn a_sigterm_to_a_relaying_front_is_open() {
    for via in [ElevatedVia::Wrapped(Backend::Sudo), ElevatedVia::Wrapped(Backend::Doas)] {
        let g = terminate_gate(Some(&via), PID, || panic!("not asked"));
        assert!(matches!(g, Gate::Open), "{via:?}: {g:?}");
    }
}

/// A `SIGTERM` would end osascript and orphan the program: refused while osascript runs, sent
/// once it has exited. Mutants: osascript's `SIGTERM` is sent; its exit is ignored.
#[skuld::test]
fn a_sigterm_to_a_live_osascript_is_closed() {
    let osascript = ElevatedVia::MacosOsascript;
    let detail = refusal_detail(terminate_gate(Some(&osascript), PID, || Ok(true)));
    assert!(detail.contains(&format!("pid {PID} is osascript")), "{detail}");
    assert!(detail.contains("no SIGTERM was sent"), "{detail}");
    let detail = refusal_detail(terminate_gate(Some(&osascript), PID, || {
        Err(io::Error::other("peek refused"))
    }));
    assert!(detail.contains("peek refused"), "{detail}");
    assert!(matches!(
        terminate_gate(Some(&osascript), PID, || Ok(false)),
        Gate::Open
    ));
}

/// What `cgroup_kill_reached` asked, in order (`l`isted, `e`xited, `u`nder the leaf), and its answer.
fn reached_asking(
    listed: io::Result<bool>,
    exited: io::Result<bool>,
    under_leaf: io::Result<bool>,
) -> (Result<(), Error>, String) {
    let asked = Cell::new(String::new());
    let note = |c: char| {
        let mut s = asked.take();
        s.push(c);
        asked.set(s);
    };
    let r = super::cgroup_kill_reached(
        Some(&ElevatedVia::Wrapped(Backend::Sudo)),
        PID,
        || {
            note('l');
            listed
        },
        || {
            note('e');
            exited
        },
        || {
            note('u');
            under_leaf
        },
    );
    (r, asked.take())
}

/// A front still listed, exited, or named under the leaf after the write was there for the kill.
/// Mutant: any of the three is ignored.
#[skuld::test]
fn a_front_in_its_leaf_after_the_kill_was_reached() {
    let (r, asked) = reached_asking(Ok(true), Ok(false), Ok(false));
    assert!(r.is_ok() && asked == "l", "{r:?} {asked}");
    let (r, asked) = reached_asking(Ok(false), Ok(true), Ok(false));
    assert!(r.is_ok() && asked == "le", "{r:?} {asked}");
    let (r, asked) = reached_asking(Ok(false), Ok(false), Ok(true));
    assert!(r.is_ok() && asked == "leu", "{r:?} {asked}");
}

/// A front none of the three places in the leaf left it before the kill: refused, and named.
/// Mutant: a front outside its leaf after the kill is reported killed.
#[skuld::test]
fn a_front_outside_its_leaf_after_the_kill_was_not_reached() {
    let (r, _) = reached_asking(Ok(false), Ok(false), Ok(false));
    let detail = refusal_detail(Gate::Closed(r.expect_err("not reached")));
    assert!(detail.contains("left the cgroup before its kill"), "{detail}");
}

/// A front whose place cannot be read is not shown reached: refused, with every reason. Mutant: an
/// unreadable place reads as reached.
#[skuld::test]
fn a_front_whose_place_after_the_kill_cannot_be_read_is_refused() {
    let (r, _) = reached_asking(
        Err(io::Error::other("procs refused")),
        Ok(false),
        Err(io::Error::other("hidepid")),
    );
    let detail = refusal_detail(Gate::Closed(r.expect_err("not shown reached")));
    assert!(detail.contains("nothing shows the cgroup kill reached it"), "{detail}");
    assert!(
        detail.contains("procs refused") && detail.contains("hidepid"),
        "{detail}"
    );
}
