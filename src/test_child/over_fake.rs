//! A [`Child`] or an [`Unreaped`] over a [`FakeProcess`]: no process exists, so every wait, look and
//! signal the child makes is answered from the fake's stated tables.

use std::collections::BTreeMap;

use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::containment::fake::FakeContains;
use crate::containment::{Attachment, Containment, Mechanism, Tree};
use crate::graceful::GracefulMechanism;
use crate::identity::{Key, ProcessId};
use crate::os_process::child::ExitRecord;
use crate::os_process::fake::{Answer, FakeProcess, ReapAnswer};
use crate::signal::Sent;
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
            tree: Tree::none(),
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

/// A root of stated answers: its kill is delivered, and its looks answer `exits`.
pub(crate) fn root_looking(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    let root = FakeProcess::new(exits).signals([Ok(Sent::Delivered)]);
    #[cfg(target_os = "macos")]
    let root = root.peeks_always(|| Ok(crate::os_process::child::PeekOutcome::Running));
    root
}

/// A child over `root` whose mechanism states that its kill reached `members`.
pub(crate) fn child_reaching(root: &FakeProcess, members: &[ProcessId]) -> Child {
    let (fake, _) = FakeContains::new(Containment::Session, false);
    child_with(root, fake.reaching(members.iter().copied()))
}

/// A child over `root` whose tree is `fake`.
pub(crate) fn child_with(root: &FakeProcess, fake: FakeContains) -> Child {
    let mut child = child_over(root);
    child.tree = Tree::contained(Mechanism::Fake(fake));
    child
}

/// What a call that signalled only an fd marker's holders was told it skipped, for a child whose
/// root's number may name another process.
#[cfg(unix)]
pub(crate) fn holders_only_skip(child: &Child) -> crate::containment::Skip {
    use crate::containment::{Refusal, Why};
    crate::containment::Skip {
        action: "signal its process group".to_owned(),
        why: Why::MayNameAnother(Refusal::Unpinned(child.pid())),
        root_alone: false,
        holders: Some(Ok(())),
    }
}

/// [`child_with`], as a tokio `Child`.
#[cfg(all(feature = "tokio", unix))]
pub(crate) fn tokio_child_with(root: &FakeProcess, fake: FakeContains) -> crate::tokio::Child {
    crate::tokio::Child {
        inner: child_with(root, fake),
    }
}

/// [`child_reaching`], as a tokio `Child`.
#[cfg(feature = "tokio")]
pub(crate) fn tokio_child_reaching(root: &FakeProcess, members: &[ProcessId]) -> crate::tokio::Child {
    crate::tokio::Child {
        inner: child_reaching(root, members),
    }
}

/// A live held member and the write end of its stdin, which ends it.
pub(crate) fn live_member() -> (Child, crate::PipeWriter, ProcessId) {
    let (member, writer) = super::held_uncontained_blocker(false);
    let id = member.id().expect(super::IDENTITY_READ);
    (member, writer, id)
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
