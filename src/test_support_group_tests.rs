use super::require_group_in;

fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |name| vars.iter().find(|(n, _)| *n == name).map(|(_, v)| v.to_string())
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
