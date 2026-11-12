use super::{after_pass, run_passes, Next};

/// Runs the sweep over passes that find `counts` in turn, and says whether it stopped on a count
/// that did not fall. A sweep that runs a pass past the last row fails the test.
fn still_forking(counts: &[usize]) -> bool {
    let mut counts = counts.iter();
    run_passes(|_| *counts.next().expect("the sweep ran a pass past the rows"))
}

#[skuld::test]
fn a_pass_that_found_nothing_converges() {
    assert_eq!(after_pass(1, 0, 0), Next::Converged);
    assert!(!still_forking(&[0]));
    assert!(!still_forking(&[3, 0]));
    assert!(!still_forking(&[5, 4, 3, 0]));
}

/// A lone shell root forks its next command at teardown: pass 1 finds the tree, pass 2 finds that
/// one fork, and pass 3 finds nothing.
#[skuld::test]
fn pass_three_runs_when_pass_two_found_something() {
    assert_eq!(after_pass(1, 0, 3), Next::Another);
    assert_eq!(after_pass(2, 1, 1), Next::Another);
    assert_eq!(after_pass(2, 1, 5), Next::Another);
    assert!(!still_forking(&[1, 1, 0]));
    assert!(!still_forking(&[1, 5, 0]));
}

#[skuld::test]
fn a_pass_runs_again_only_while_the_count_falls() {
    assert_eq!(after_pass(4, 4, 3), Next::Another);
    assert_eq!(after_pass(4, 3, 3), Next::StillForking);
    // Pass 3 is the first pass the count is compared on.
    assert_eq!(after_pass(3, 2, 2), Next::StillForking);
    assert_eq!(after_pass(3, 2, 3), Next::StillForking);
    assert_eq!(after_pass(3, 2, 1), Next::Another);
    assert!(!still_forking(&[5, 4, 3, 0]));
    assert!(still_forking(&[5, 4, 3, 3]));
    assert!(still_forking(&[5, 3, 3]));
    assert!(still_forking(&[1, 1, 1]));
    assert!(still_forking(&[2, 5, 6]));
}

/// Only pass 1 is the first pass, and the passes are numbered from 1 without gaps.
#[skuld::test]
fn passes_are_numbered_from_one() {
    let mut numbers = Vec::new();
    let mut counts = [5, 4, 0].into_iter();
    run_passes(|pass| {
        numbers.push(pass);
        counts.next().expect("the sweep ran a pass past the rows")
    });
    assert_eq!(numbers, [1, 2, 3]);
}
