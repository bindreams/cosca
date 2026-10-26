//! Which `CTRL_BREAK`s the crate sent from this process, for the probes that read a target's
//! acknowledgement of one. A break that was never sent leaves that read waiting for ever, so a
//! probe reads only after [`sent_to`] says one went out, and otherwise reports it unsent.

use std::sync::{Mutex, PoisonError};

static SENT: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Start recording. Once per process, before the call under test.
pub fn install() {
    cosca::set_ctrl_break_sent_hook(|group| SENT.lock().unwrap_or_else(PoisonError::into_inner).push(group));
}

/// Whether the breaks sent since the last call were exactly one, to the group led by `group`.
pub fn sent_to(group: u32) -> bool {
    let sent = std::mem::take(&mut *SENT.lock().unwrap_or_else(PoisonError::into_inner));
    sent == [group]
}
