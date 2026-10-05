//! Async twin of `child/front_failed_closed_tests.rs`.

use crate::child::front_failed_closed_tests::{assert_case, cases, failed_closed_spawn};
use crate::test_groups::{cgroup, Group};

#[skuld::test]
async fn cgroup_a_failed_closed_verdict_is_acted_on_by_where_the_child_stands(#[fixture(cgroup)] _group: &Group) {
    for case in cases() {
        let (err, pid, stdin) = failed_closed_spawn(case, |cmd| crate::tokio::spawn::spawn(cmd).map(drop));
        assert_case(case, &err, pid, stdin);
    }
}
