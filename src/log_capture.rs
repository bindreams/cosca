//! Minimal capturing logger: installed once per process (`log::set_logger` is
//! once-per-process); records every message so tests assert by unique marker.
//!
//! Records are append-only and never erased: each test takes a [`mark`] and scans
//! only records emitted after it via [`contains_since`], so a stale record from an
//! earlier test (e.g. a same-shape marker under OS pid reuse) can never satisfy an
//! assertion, and no test can erase another's records.

use std::sync::{Mutex, OnceLock};

struct CaptureLog;
static RECORDS: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());
static INSTALLED: OnceLock<()> = OnceLock::new();

impl log::Log for CaptureLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        RECORDS
            .lock()
            .unwrap()
            .push((record.level(), record.args().to_string()));
    }
    fn flush(&self) {}
}

pub(crate) fn install() {
    INSTALLED.get_or_init(|| {
        log::set_logger(&CaptureLog).expect("first logger in this test process");
        log::set_max_level(log::LevelFilter::Trace);
    });
}

/// Current end of the record buffer — scan from here with [`contains_since`].
pub(crate) fn mark() -> usize {
    RECORDS.lock().unwrap().len()
}

/// True if any record emitted at or after `mark` contains `marker`. Never panics:
/// records are append-only, so `mark` (a past length) is always in bounds.
pub(crate) fn contains_since(mark: usize, marker: &str) -> bool {
    RECORDS.lock().unwrap()[mark..].iter().any(|(_, m)| m.contains(marker))
}

/// The levels of every record emitted at or after `mark` that contains `marker`.
///
/// A level is part of a log record's meaning, not decoration: it is what decides whether an
/// embedder's sink shows the message by default. Assertions about "this condition must not be
/// narrated at `warn`" are therefore assertions about the level, which [`contains_since`]
/// cannot see.
pub(crate) fn levels_since(mark: usize, marker: &str) -> Vec<log::Level> {
    RECORDS.lock().unwrap()[mark..]
        .iter()
        .filter(|(_, m)| m.contains(marker))
        .map(|(level, _)| *level)
        .collect()
}

#[cfg(test)]
#[path = "log_capture_tests.rs"]
mod log_capture_tests;
