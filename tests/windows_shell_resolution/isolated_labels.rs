//! The probes that run alone are each selected by a label of their own, on top of the group's.

use crate::test_harness::{ISOLATED_EXISTING_EXTENSIONLESS, ISOLATED_PATHEXT_PRECEDENCE, ISOLATED_TRAILING_DOT};

/// The names of the tests in this binary that carry `label` themselves.
fn carriers(label: skuld::Label) -> Vec<&'static str> {
    skuld::test_registry()
        .values()
        .filter(|def| def.labels.contains(&label))
        .map(|def| def.name)
        .collect()
}

/// Mutant: an isolated probe loses its label (its step selects nothing), or another probe gains it
/// (that probe then runs twice, once of them not alone).
#[skuld::test]
fn each_isolated_label_selects_its_one_probe() {
    for (label, probe) in [
        (
            ISOLATED_TRAILING_DOT,
            "does_a_trailing_dot_still_open_the_extensionless_file",
        ),
        (
            ISOLATED_PATHEXT_PRECEDENCE,
            "does_pathext_outrank_an_existing_extensionless_file",
        ),
        (
            ISOLATED_EXISTING_EXTENSIONLESS,
            "does_an_existing_extensionless_file_ever_launch_directly",
        ),
    ] {
        assert_eq!(carriers(label), [probe], "{label}");
    }
}

/// Mutant: an isolated probe drops the group fixture, so the executing step, which excludes the
/// isolated labels from `shell_probes`, never runs it at all and its own step runs it ungated.
#[skuld::test]
fn each_isolated_probe_is_still_in_the_shell_probes_group() {
    for label in [
        ISOLATED_TRAILING_DOT,
        ISOLATED_PATHEXT_PRECEDENCE,
        ISOLATED_EXISTING_EXTENSIONLESS,
    ] {
        for def in skuld::test_registry()
            .values()
            .filter(|def| def.labels.contains(&label))
        {
            assert_eq!(
                skuld::fixture::collect_fixture_labels(def.fixture_names),
                [crate::test_harness::SHELL_PROBES],
                "{}",
                def.name
            );
        }
    }
}
