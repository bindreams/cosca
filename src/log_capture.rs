//! Minimal capturing logger: installed once per process (`log::set_logger` is
//! once-per-process); records every message so tests assert by unique marker.
//!
//! Records are append-only and never erased: each test takes a [`mark`] and scans
//! only records emitted after it via [`contains_since`], so a stale record from an
//! earlier test (e.g. a same-shape marker under OS pid reuse) can never satisfy an
//! assertion, and no test can erase another's records.

use std::sync::{Mutex, OnceLock};
use std::thread::ThreadId;

struct CaptureLog;
static RECORDS: Mutex<Vec<(log::Level, String, ThreadId)>> = Mutex::new(Vec::new());
static INSTALLED: OnceLock<()> = OnceLock::new();

thread_local! {
    static PANIC_ON: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// While the guard lives, a record emitted by THIS thread that contains `marker` is captured and
/// then panics out of the logger, as an untrusted `Log` impl may.
#[cfg(all(test, unix, feature = "tokio"))]
pub(crate) fn panic_on(marker: &str) -> PanicOn {
    PANIC_ON.with(|p| *p.borrow_mut() = Some(marker.to_owned()));
    PanicOn(())
}

#[cfg(all(test, unix, feature = "tokio"))]
#[must_use = "the panicking logger ends when the guard drops"]
pub(crate) struct PanicOn(());

#[cfg(all(test, unix, feature = "tokio"))]
impl Drop for PanicOn {
    fn drop(&mut self) {
        PANIC_ON.with(|p| *p.borrow_mut() = None);
    }
}

impl log::Log for CaptureLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        let text = record.args().to_string();
        RECORDS
            .lock()
            .unwrap()
            .push((record.level(), text.clone(), std::thread::current().id()));
        let armed = PANIC_ON.with(|p| p.borrow().as_ref().is_some_and(|marker| text.contains(marker.as_str())));
        if armed {
            panic!("forced logger panic (test seam)");
        }
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
    RECORDS.lock().unwrap()[mark..]
        .iter()
        .any(|(_, m, _)| m.contains(marker))
}

/// The text of every record emitted at or after `mark` that contains `marker`.
pub(crate) fn records_since(mark: usize, marker: &str) -> Vec<String> {
    RECORDS.lock().unwrap()[mark..]
        .iter()
        .filter(|(_, m, _)| m.contains(marker))
        .map(|(_, m, _)| m.clone())
        .collect()
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
        .filter(|(_, m, _)| m.contains(marker))
        .map(|(level, _, _)| *level)
        .collect()
}

/// Like [`records_since`], but only records emitted by the CALLING thread. For a marker that is
/// a constant message prefix shared by every test in the process, this is what keeps a
/// concurrently-running test's identical record from satisfying (or breaking) the assertion.
#[cfg(test)]
pub(crate) fn records_since_on_current_thread(mark: usize, marker: &str) -> Vec<(log::Level, String)> {
    let me = std::thread::current().id();
    RECORDS.lock().unwrap()[mark..]
        .iter()
        .filter(|(_, m, t)| *t == me && m.contains(marker))
        .map(|(level, m, _)| (*level, m.clone()))
        .collect()
}

#[cfg(test)]
#[path = "log_capture_tests.rs"]
mod log_capture_tests;
