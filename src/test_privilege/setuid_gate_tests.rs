//! Unit tests for the gate in [`super::setuid`].

use super::setuid::{setuid_gate, Gate};

fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |k| pairs.iter().find(|(name, _)| *name == k).map(|(_, v)| (*v).to_owned())
}

#[skuld::test]
fn setuid_gate_zero_disables_the_group() {
    assert_eq!(setuid_gate(env(&[("COSCA_TEST_SETUID", "0")])), Gate::Disabled);
}

#[skuld::test]
fn setuid_gate_zero_disables_it_even_with_consent() {
    let vars = [("COSCA_TEST_SETUID", "0"), ("COSCA_TEST_SETUID_CONSENT", "1")];
    assert_eq!(setuid_gate(env(&vars)), Gate::Disabled);
}

#[skuld::test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_unset_group_and_consent_panics() {
    setuid_gate(env(&[]));
}

#[skuld::test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_group_on_without_consent_panics() {
    setuid_gate(env(&[("COSCA_TEST_SETUID", "1")]));
}

#[skuld::test]
#[should_panic(expected = "COSCA_TEST_SETUID_CONSENT")]
fn setuid_gate_consent_other_than_one_panics() {
    setuid_gate(env(&[("COSCA_TEST_SETUID_CONSENT", "yes")]));
}

#[skuld::test]
fn setuid_gate_names_both_variables_in_the_panic() {
    let msg = std::panic::catch_unwind(|| setuid_gate(env(&[]))).unwrap_err();
    let msg = msg.downcast_ref::<String>().expect("a formatted panic message");
    assert!(
        msg.contains("COSCA_TEST_SETUID_CONSENT") && msg.contains("COSCA_TEST_SETUID=0"),
        "{msg}"
    );
}

#[skuld::test]
fn setuid_gate_consent_one_runs() {
    assert_eq!(setuid_gate(env(&[("COSCA_TEST_SETUID_CONSENT", "1")])), Gate::Run);
}

#[skuld::test]
fn setuid_gate_any_group_value_but_zero_runs_with_consent() {
    let vars = [("COSCA_TEST_SETUID", "yes"), ("COSCA_TEST_SETUID_CONSENT", "1")];
    assert_eq!(setuid_gate(env(&vars)), Gate::Run);
}
