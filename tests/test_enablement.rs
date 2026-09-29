//! `common::require_group`'s cases, run over an explicit environment.

#[path = "common/mod.rs"]
mod common;

use common::test_enablement::require_group_in;

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| vars.iter().find(|(k, _)| *k == name).map(|(_, v)| v.to_string())
}

#[test]
fn an_explicit_zero_disables_the_group_without_asking_for_consent() {
    assert!(!require_group_in("CGROUP", env(&[("COSCA_TEST_CGROUP", "0")])));
}

#[test]
fn consent_of_exactly_one_enables_the_group() {
    assert!(require_group_in("CGROUP", env(&[("COSCA_TEST_CGROUP_CONSENT", "1")])));
    assert!(require_group_in(
        "CGROUP",
        env(&[("COSCA_TEST_CGROUP", "1"), ("COSCA_TEST_CGROUP_CONSENT", "1")])
    ));
}

#[test]
#[should_panic(expected = "COSCA_TEST_CGROUP_CONSENT=1")]
fn an_unset_group_without_consent_fails_rather_than_skips() {
    require_group_in("CGROUP", env(&[]));
}

#[test]
#[should_panic(expected = "COSCA_TEST_CGROUP_CONSENT=1")]
fn any_consent_but_exactly_one_fails() {
    require_group_in("CGROUP", env(&[("COSCA_TEST_CGROUP_CONSENT", "yes")]));
}

#[test]
#[should_panic(expected = "COSCA_TEST_CGROUP_CONSENT=1")]
fn any_group_value_but_zero_runs_the_group_and_so_needs_consent() {
    require_group_in("CGROUP", env(&[("COSCA_TEST_CGROUP", "false")]));
}
