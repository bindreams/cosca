//! A [`Child`] or an [`Unreaped`] over a [`FakeProcess`]: no process exists, so every wait, look and
//! signal the child makes is answered from the fake's stated tables.

use std::collections::BTreeMap;

use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::containment::{Attachment, Tree};
use crate::graceful::GracefulMechanism;
use crate::identity::{Key, ProcessId};
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::{FakeProcess, ReapAnswer};
use crate::{Child, Unreaped};

/// No process has this number, so a call that went by number instead of through the fake would
/// find nothing to signal.
const ABSENT_PID: u32 = 0x7fff_fffe;

/// An uncontained `Child` over `fake`, which the test keeps to script and read it. It does not
/// kill on drop. The fake answers [`ABSENT_PID`] to the child's pid, as its identity names it.
pub(crate) fn child_over(fake: &FakeProcess) -> Child {
    Child::from_parts(
        OwnedChild::new(Box::new(fake.clone().with_pid(ABSENT_PID))),
        Some(ProcessId::from_parts_for_test(ABSENT_PID, Key::for_test(1))),
        BTreeMap::new(),
        false,
        Attachment {
            tree: Tree::None,
            graceful: if cfg!(windows) {
                GracefulMechanism::None
            } else {
                GracefulMechanism::Process
            },
        },
        None,
        SpawnPolicy::SYNC,
    )
}

pub(crate) fn unreaped_over(fake: &FakeProcess, id: Option<ProcessId>) -> Unreaped {
    Unreaped::new(
        OwnedChild::new(Box::new(fake.clone())),
        id,
        false,
        SpawnPolicy::SYNC.unreaped_drop,
    )
}

/// A boxed `Unreaped` over a fake that has exited, so dropping it waits for nothing.
pub(crate) fn exited_unreaped(id: ProcessId) -> Box<Unreaped> {
    let exit = ExitRecord::Status(std::process::ExitStatus::default());
    let fake = FakeProcess::new([])
        .with_pid(id.pid())
        .reaps([ReapAnswer::Reaped(exit)]);
    Box::new(unreaped_over(&fake, Some(id)))
}
