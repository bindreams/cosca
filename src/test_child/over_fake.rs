//! A [`Child`] over a [`FakeProcess`]: no process exists, so every wait, look and signal the child
//! makes is answered from the fake's stated tables.

use std::collections::BTreeMap;

use crate::child::owned::OwnedChild;
use crate::containment::{Attached, Attachment, Containment};
use crate::graceful::GracefulMechanism;
use crate::identity::ProcessId;
use crate::os_process::fake::FakeProcess;
use crate::Child;

/// No process has this number, so a call that went by number instead of through the fake would
/// find nothing to signal.
const ABSENT_PID: u32 = 0x7fff_fffe;

/// An uncontained `Child` over `fake`, which the test keeps to script and read it. It does not
/// kill on drop.
pub(crate) fn child_over(fake: &FakeProcess) -> Child {
    Child::from_parts(
        OwnedChild::new(Box::new(fake.clone())),
        ProcessId::from_parts(ABSENT_PID, 1),
        BTreeMap::new(),
        false,
        Attachment {
            containment: Containment::None,
            attached: Attached::None,
            graceful: if cfg!(windows) {
                GracefulMechanism::None
            } else {
                GracefulMechanism::Process
            },
        },
    )
}
