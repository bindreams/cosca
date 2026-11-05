//! Linux: the sync spawn's teardown of the child it holds once the handshake has given it a pidfd,
//! when the identity read or the attach that follows fails.
//!
//! The child is an [`OwnedChild`] from the moment the handshake succeeds, so the teardown is
//! [`OwnedChild::tear_down`], and the caller's rule for a child that still runs applies: it is handed
//! back in the error ([`Disposition::HandBack`]).

use super::{Diagnosis, FrontFate};
use crate::child::owned::teardown::{Disposition, Reach, TeardownKind};
use crate::child::owned::OwnedChild;
use crate::containment::cgroup::Subtree;
use crate::containment::dispatch::TeardownCaller;
use crate::elevation::front::Front;
use crate::error::{ChildFate, Error};
use crate::identity::ProcessId;
use crate::Unreaped;

/// Tears `child`, the sync spawn's child `pid`, down after `error` failed the spawn, and returns
/// `error` with what became of the child, the child's fate, and the child itself if it still runs.
///
/// A child that is not a front is killed and reaped. A front (`front`) is sent nothing and looked
/// at: reaped if it has exited, waited for if `subtree`, where its leaf's kill went, shows that kill
/// reached it, and otherwise running. `id` is the child's identity, if the spawn read one. `why`
/// leads the teardown's one warn, if it has one.
pub(crate) fn tear_down_held(
    child: OwnedChild,
    pid: u32,
    front: Option<Front>,
    id: Option<ProcessId>,
    subtree: Option<&Subtree>,
    why: &mut Diagnosis,
    error: Error,
) -> (Error, ChildFate, Option<Unreaped>) {
    let disposition = Disposition::HandBack;
    let (front_fate, torn) = if front.is_some() {
        let reach = Ok(subtree.map(|subtree| subtree as &dyn Reach));
        let torn = child.tear_down(id, TeardownKind::Look(reach), None);
        let fate = torn.look.as_ref().map(FrontFate::of_look);
        let worded = crate::child::word_front(TeardownCaller::FailedSpawn, pid, &"its spawn failed", disposition, torn);
        (fate, worded)
    } else {
        let tree = None;
        (
            None,
            child.tear_down(id, TeardownKind::Kill { disposition, tree }, None),
        )
    };
    if let Some(left) = &torn.left {
        log::warn!("{}", why.fold(left));
    }
    let unreaped = disposition.hands_back(&torn).then(|| Unreaped::new(child, id));
    let error = match front_fate {
        Some(fate) if unreaped.is_some() => fate.note_handed_back(error, front, Some(pid)),
        Some(fate) => fate.note(error, front, Some(pid)),
        None => error,
    };
    (error, torn.fate, unreaped)
}
