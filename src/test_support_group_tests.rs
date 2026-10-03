use super::{check_group, require_group_in};

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| vars.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

/// Mutant: the group variable is required to be set.
#[skuld::test]
fn an_unset_group_variable_with_consent_runs() {
    assert_eq!(
        check_group("TRACER", env(&[("COSCA_TEST_TRACER_CONSENT", "1")])),
        Ok(true)
    );
}

/// Mutant: only `1` enables.
#[skuld::test]
fn any_group_value_but_0_runs() {
    let vars = [("COSCA_TEST_TRACER", "2"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    assert_eq!(check_group("TRACER", env(&vars)), Ok(true));
}

/// Mutant: `0` is ignored.
#[skuld::test]
fn group_0_turns_the_group_off() {
    let vars = [("COSCA_TEST_TRACER", "0"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    assert_eq!(check_group("TRACER", env(&vars)), Ok(false));
}

/// Consent is asked only of an enabled group. Mutant: consent is checked before `=0`.
#[skuld::test]
fn group_0_needs_no_consent() {
    assert_eq!(check_group("TRACER", env(&[("COSCA_TEST_TRACER", "0")])), Ok(false));
}

/// Mutant: consent defaults to given.
#[skuld::test]
fn unset_consent_fails_and_names_the_variables() {
    let why = check_group("TRACER", env(&[])).unwrap_err();
    assert!(
        why.contains("COSCA_TEST_TRACER_CONSENT=1") && why.contains("COSCA_TEST_TRACER=0"),
        "{why}"
    );
}

/// Mutant: any non-empty consent counts.
#[skuld::test]
fn consent_other_than_1_fails() {
    for value in ["0", "yes", "true", " 1", ""] {
        let vars = [("COSCA_TEST_TRACER_CONSENT", value)];
        assert!(
            check_group("TRACER", env(&vars)).is_err(),
            "consent {value:?} was accepted"
        );
    }
}

/// Mutant: `require_group` returns `false` instead of failing.
#[skuld::test]
#[should_panic(expected = "set COSCA_TEST_TRACER_CONSENT=1")]
fn require_group_fails_without_consent() {
    require_group_in("TRACER", env(&[]));
}

/// Mutant: `require_group` ignores the rule's answer.
#[skuld::test]
fn require_group_passes_the_answer_on() {
    assert!(!require_group_in("TRACER", env(&[("COSCA_TEST_TRACER", "0")])));
    assert!(require_group_in("TRACER", env(&[("COSCA_TEST_TRACER_CONSENT", "1")])));
}
