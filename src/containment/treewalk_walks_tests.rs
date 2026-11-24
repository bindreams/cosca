//! The walks and queries a test runs over a kernel it states: each of the four that kill or signal a
//! tree, over an identity or an open handle on it, and the two `children` queries. Unix: the macOS and
//! Linux walk tests share them.

use crate::containment::dispatch::Unkilled;
use crate::error::Error;
use crate::identity::{Kernel, ProcessId};
use crate::test_child::open_live;
use crate::Recursive;

pub(super) type Walk = fn(&dyn Kernel, ProcessId) -> Result<(), Error>;

/// The walks that take an identity.
pub(super) fn id_walks() -> [(&'static str, Walk); 2] {
    [
        ("hard_kill", |k, id| {
            super::hard_kill(k, id, &super::ByIdentity::new(k, id))
                .outcome()
                .into_result()
                .map_err(Unkilled::into_error)
        }),
        ("terminate", |k, id| {
            super::terminate(
                k,
                id,
                &super::ByIdentity::new(k, id),
                crate::containment::TreeStop::default(),
            )
            .0
            .into_tree_result()
        }),
    ]
}

/// Every walk, `Process`'s included, over an open handle on the live `id`.
pub(super) fn walks() -> [(&'static str, Walk); 4] {
    let [hard_kill, terminate] = id_walks();
    [
        hard_kill,
        terminate,
        ("kill_tree", |k, id| open_live(id).kill_tree_with("kill_tree", k)),
        ("terminate_tree", |k, id| {
            open_live(id).terminate_tree_with(k).map_err(Error::from)
        }),
    ]
}

pub(super) type Query = fn(&ProcessId, &dyn Kernel) -> Result<(), Error>;

/// The queries that take the process snapshot. `parent` does not: it reads `self` alone.
pub(super) fn children_queries() -> [(&'static str, Query); 2] {
    [
        ("children(No)", |p, k| p.children_with(k, Recursive::No).map(|_| ())),
        ("children(Yes)", |p, k| p.children_with(k, Recursive::Yes).map(|_| ())),
    ]
}
