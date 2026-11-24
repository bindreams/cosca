//! A [`Child`] or an [`Unreaped`] over a [`FakeProcess`]: no process exists, so every wait, look and
//! signal the child makes is answered from the fake's stated tables.

use std::collections::BTreeMap;

use crate::child::owned::OwnedChild;
use crate::child::spawn::policy::SpawnPolicy;
use crate::containment::fake::FakeContains;
use crate::containment::{Attachment, Containment, Mechanism, Tree};
use crate::elevation::front::TrackedKind;
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
        OwnedChild::new(Box::new(fake.clone().with_pid(ABSENT_PID)), TrackedKind::Own),
        Some(ProcessId::from_parts_for_test(ABSENT_PID, Key::for_test(1))),
        BTreeMap::new(),
        false,
        Attachment {
            tree: Tree::none(),
            #[cfg(windows)]
            console: Default::default(),
        },
        None,
        SpawnPolicy::SYNC,
        stop_over_a_fake(),
        #[cfg(windows)]
        Default::default(),
    )
}

/// The stop of a child over a fake. Unix: the default, which sends through the fake's tables. Windows: the
/// default would send a `CTRL_BREAK` to a pid no process has, through the OS, so the action states a break
/// that went out ([`stated_break`]).
fn stop_over_a_fake() -> crate::stop::StopAction {
    #[cfg(unix)]
    return crate::stop::StopAction::default();
    #[cfg(windows)]
    return crate::stop::StopAction::sync(stated_break);
}

/// Windows: a break that went out, as a stop over a fake states it: a tree target hands the fake mechanism
/// the answer of that send, and a root target sends nothing.
#[cfg(windows)]
fn stated_break(target: &crate::StopTarget<'_>) -> Result<(), crate::error::Error> {
    match target.scope() {
        crate::stop::Scope::Root => Ok(()),
        crate::stop::Scope::Tree(call) => target.send_tree(
            call,
            crate::containment::TreeStop::named(
                crate::stop::proxy::protocol::CtrlEvent::CtrlBreak.name(),
                crate::containment::SendAnswer::Sent(Ok(())),
            ),
        ),
    }
}

/// A root of stated answers: its kill is delivered, and its looks answer `exits`. The kernel it lends to
/// the policy layer (`OsChild::kernel`) is the host's, for the calls that borrow one and read nothing
/// through it.
pub(crate) fn root_looking(exits: impl IntoIterator<Item = Answer>) -> FakeProcess {
    let root = FakeProcess::new(exits)
        .signals([Ok(Sent::Delivered)])
        .with_kernel(crate::identity::spawn_kernel(crate::identity::HostKernel));
    #[cfg(target_os = "macos")]
    let root = root.peeks_always(|| Ok(crate::os_process::child::PeekOutcome::Running));
    root
}

/// A fake root for a shutdown that grace-waits, kills and reaps it: the reap's first look finds it running, so a
/// reap whose deadline has passed ends there, and any other goes on to the exit. Its grace looks answer
/// `grace_looks`, and the kill is delivered.
pub(crate) fn killed_root(grace_looks: impl IntoIterator<Item = Answer>) -> FakeProcess {
    root_looking(grace_looks)
        .signals([Ok(Sent::Delivered), Ok(Sent::Delivered)])
        .reaps([
            ReapAnswer::Running,
            ReapAnswer::Exited(ExitRecord::Status(std::process::ExitStatus::default())),
        ])
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
        why: Why::MayNameAnother(Refusal::Unpinned(child.pid()), None),
        root_alone: false,
        no_holder_reached: false,
        holders: Some(Ok(())),
    }
}

/// [`child_reaching`], as a tokio `Child`.
#[cfg(feature = "tokio")]
pub(crate) fn tokio_child_reaching(root: &FakeProcess, members: &[ProcessId]) -> crate::tokio::Child {
    #[cfg_attr(unix, allow(unused_mut, reason = "only Windows swaps the stop for an async one"))]
    let mut inner = child_reaching(root, members);
    #[cfg(windows)]
    {
        inner.stop = crate::stop::StopAction::asynchronous(|target| Box::pin(async move { stated_break(target) }));
    }
    crate::tokio::Child { inner }
}

/// A live held member and the write end of its stdin, which ends it.
pub(crate) fn live_member() -> (Child, crate::PipeWriter, ProcessId) {
    let (member, writer) = super::held_uncontained_blocker(false);
    let id = member.id().expect(super::IDENTITY_READ);
    (member, writer, id)
}

pub(crate) fn unreaped_over(fake: &FakeProcess, id: Option<ProcessId>) -> Unreaped {
    Unreaped::new(
        OwnedChild::new(Box::new(fake.clone()), TrackedKind::Own),
        id,
        SpawnPolicy::SYNC.unreaped_drop,
    )
}

/// A boxed `Unreaped` over a fake that has exited, so dropping it waits for nothing.
pub(crate) fn exited_unreaped(id: ProcessId) -> Box<Unreaped> {
    let exit = ExitRecord::Status(std::process::ExitStatus::default());
    let fake = FakeProcess::new([])
        .with_pid(id.pid())
        .reaps([ReapAnswer::Exited(exit)]);
    Box::new(unreaped_over(&fake, Some(id)))
}
