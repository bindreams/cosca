//! A stated-facts [`Kernel`]: the answers its rows hold, and nothing the kernel would do. A call
//! with no row left panics, naming the call: a test states every call the code under test makes.
//!
//! The rows of a call kind are taken in the order they were stated, and each answers one call. A
//! refusing row answers without calling `TerminateProcess`: the process stays alive. Rows are
//! keyed by call order, not by handle: a test driving several terminates through one kernel states
//! them in that order.

use std::collections::VecDeque;
use std::sync::Mutex;

use windows::core::HRESULT;
use windows::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE};

use super::{Kernel, StartupRead};
use crate::identity::Key;

pub(crate) struct FakeKernel {
    /// The answers of the `creation_token` calls, in call order; `Err` is the failure's `HRESULT`.
    creation_tokens: Mutex<VecDeque<Result<Key, HRESULT>>>,
    /// The answers of the `terminate` calls, in call order; `Err` is the failure's `HRESULT`.
    terminates: Mutex<VecDeque<Result<(), HRESULT>>>,
    /// The answers of the `start_state` calls, in call order.
    start_states: Mutex<VecDeque<std::io::Result<StartupRead>>>,
}

/// The refusal `TerminateProcess` gives a process that is exiting, or a handle without
/// `PROCESS_TERMINATE`: `ERROR_ACCESS_DENIED`.
fn access_denied() -> HRESULT {
    HRESULT::from_win32(ERROR_ACCESS_DENIED.0)
}

/// A kernel whose one `terminate` is refused as an exit under way. A second call panics.
pub(crate) fn refusing_the_next_terminate() -> FakeKernel {
    FakeKernel::new().on_terminate(Err(access_denied()))
}

impl FakeKernel {
    pub(crate) fn new() -> Self {
        FakeKernel {
            creation_tokens: Mutex::new(VecDeque::new()),
            terminates: Mutex::new(VecDeque::new()),
            start_states: Mutex::new(VecDeque::new()),
        }
    }

    /// The next `creation_token` call after the earlier rows answers `answer`, and reads nothing.
    pub(crate) fn on_creation_token(mut self, answer: Result<Key, HRESULT>) -> Self {
        self.creation_tokens
            .get_mut()
            .expect("no thread holds the rows")
            .push_back(answer);
        self
    }

    /// The next `terminate` call after the earlier rows answers `answer`, and calls nothing.
    pub(crate) fn on_terminate(mut self, answer: Result<(), HRESULT>) -> Self {
        self.terminates
            .get_mut()
            .expect("no thread holds the rows")
            .push_back(answer);
        self
    }

    /// The next `start_state` call after the earlier rows answers `answer`, and reads nothing.
    pub(crate) fn on_start_state(mut self, answer: std::io::Result<StartupRead>) -> Self {
        self.start_states
            .get_mut()
            .expect("no thread holds the rows")
            .push_back(answer);
        self
    }

    /// Whether every stated row has answered a call. A row left over is a call the test expected and
    /// the code never made, or made in another order.
    pub(crate) fn all_rows_taken(&self) -> bool {
        self.terminates
            .lock()
            .expect("no thread panics holding the rows")
            .is_empty()
            && self
                .creation_tokens
                .lock()
                .expect("no thread panics holding the rows")
                .is_empty()
            && self
                .start_states
                .lock()
                .expect("no thread panics holding the rows")
                .is_empty()
    }
}

impl Kernel for FakeKernel {
    fn creation_token(&self, _handle: HANDLE) -> windows::core::Result<Key> {
        let row = self
            .creation_tokens
            .lock()
            .expect("no thread panics holding the rows")
            .pop_front();
        match row.expect("the fake kernel has no row left for creation_token") {
            Ok(key) => Ok(key),
            Err(code) => Err(windows::core::Error::from_hresult(code)),
        }
    }

    fn terminate(&self, _handle: HANDLE, _exit_code: u32) -> windows::core::Result<()> {
        let row = self
            .terminates
            .lock()
            .expect("no thread panics holding the rows")
            .pop_front();
        match row.expect("the fake kernel has no row left for terminate") {
            Ok(()) => Ok(()),
            Err(code) => Err(windows::core::Error::from_hresult(code)),
        }
    }

    fn start_state(&self, _handle: HANDLE) -> std::io::Result<StartupRead> {
        self.start_states
            .lock()
            .expect("no thread panics holding the rows")
            .pop_front()
            .expect("the fake kernel has no row left for start_state")
    }
}
