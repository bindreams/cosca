use super::{ContainMode, Containment, Nesting};

#[skuld::test]
fn containment_display_names_the_mechanism() {
    assert_eq!(Containment::JobObject.to_string(), "job object");
    assert_eq!(Containment::CgroupV2.to_string(), "cgroup v2");
    assert_eq!(Containment::ProcessGroup.to_string(), "process group");
    assert_eq!(Containment::Session.to_string(), "session");
    assert_eq!(Containment::FdMarker.to_string(), "inherited-fd marker");
    assert_eq!(Containment::TreeWalk.to_string(), "process-tree walk");
    assert_eq!(Containment::Delegated.to_string(), "delegated");
    assert_eq!(Containment::None.to_string(), "none");
}

#[skuld::test]
fn containment_can_teardown() {
    assert!(!Containment::None.can_teardown());
    assert!(!Containment::Delegated.can_teardown());
    for c in [
        Containment::CgroupV2,
        Containment::JobObject,
        Containment::ProcessGroup,
        Containment::Session,
        Containment::FdMarker,
        Containment::TreeWalk,
    ] {
        assert!(c.can_teardown(), "{c:?} must be teardown-capable");
    }
}

#[skuld::test]
fn nesting_defaults_to_mark() {
    assert_eq!(Nesting::default(), Nesting::Mark);
}

#[skuld::test]
fn contain_modes_are_distinct() {
    assert_ne!(ContainMode::Strongest, ContainMode::TreeWalk);
}

#[skuld::test]
fn contain_mode_session_is_distinct_from_strongest_and_treewalk() {
    assert_ne!(ContainMode::Session, ContainMode::Strongest);
    assert_ne!(ContainMode::Session, ContainMode::TreeWalk);
}
