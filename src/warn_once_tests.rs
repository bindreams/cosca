use std::collections::BTreeSet;
use std::sync::{Arc, Barrier, Mutex};

use super::report_level;

#[test]
fn a_condition_warns_the_first_time_and_is_debug_after() {
    let seen = Mutex::new(BTreeSet::new());
    assert_eq!(report_level(&seen, "a"), log::Level::Warn);
    assert_eq!(report_level(&seen, "a"), log::Level::Debug);
    assert_eq!(report_level(&seen, "a"), log::Level::Debug);
}

#[test]
fn a_distinct_condition_warns_again() {
    let seen = Mutex::new(BTreeSet::new());
    assert_eq!(report_level(&seen, 1), log::Level::Warn);
    assert_eq!(report_level(&seen, 2), log::Level::Warn);
    assert_eq!(report_level(&seen, 1), log::Level::Debug);
}

/// Threads meeting one condition for the first time together get exactly one `Warn`: they are
/// released at once by a barrier, and the set's lock decides which one is first.
#[test]
fn concurrent_first_meetings_warn_exactly_once() {
    const THREADS: usize = 8;
    let seen = Arc::new(Mutex::new(BTreeSet::new()));
    let start = Arc::new(Barrier::new(THREADS));
    let levels: Vec<log::Level> = (0..THREADS)
        .map(|_| {
            let (seen, start) = (seen.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                report_level(&seen, "shared")
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().expect("a reporting thread"))
        .collect();
    assert_eq!(levels.iter().filter(|&&level| level == log::Level::Warn).count(), 1);
    assert_eq!(
        levels.iter().filter(|&&level| level == log::Level::Debug).count(),
        THREADS - 1
    );
}
