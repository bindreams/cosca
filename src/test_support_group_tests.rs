use super::check_group;

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| vars.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
}

/// Mutant: the group variable is required to be set (would refuse an unset one).
#[test]
fn an_unset_group_variable_with_consent_runs() {
    assert_eq!(
        check_group("TRACER", env(&[("COSCA_TEST_TRACER_CONSENT", "1")])),
        Ok(())
    );
}

/// Mutant: only `1` enables (would refuse `2`).
#[test]
fn any_group_value_but_0_runs() {
    let vars = [("COSCA_TEST_TRACER", "2"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    assert_eq!(check_group("TRACER", env(&vars)), Ok(()));
}

/// Mutant: `0` is honoured by returning early (would be `Ok`).
#[test]
fn group_0_fails_and_names_the_filter() {
    let vars = [("COSCA_TEST_TRACER", "0"), ("COSCA_TEST_TRACER_CONSENT", "1")];
    let why = check_group("TRACER", env(&vars)).unwrap_err();
    assert!(
        why.contains("COSCA_TEST_TRACER=0") && why.contains("not test(/tracer/)"),
        "{why}"
    );
}

/// Names the consent and the explicit opt-out. Mutant: consent defaults to given (would be
/// `Ok`).
#[test]
fn unset_consent_fails_and_names_the_variable() {
    let why = check_group("TRACER", env(&[])).unwrap_err();
    assert!(
        why.contains("COSCA_TEST_TRACER_CONSENT=1")
            && why.contains("COSCA_TEST_TRACER=0")
            && why.contains("not test(/tracer/)"),
        "{why}"
    );
}

/// Mutant: any non-empty consent counts (would be `Ok`).
#[test]
fn consent_other_than_1_fails() {
    for value in ["0", "yes", "true", " 1", ""] {
        let vars = [("COSCA_TEST_TRACER_CONSENT", value)];
        assert!(
            check_group("TRACER", env(&vars)).is_err(),
            "consent {value:?} was accepted"
        );
    }
}
