//! What a leaf's `cgroup.kill` writes answered: the one record every removal of the leaf reads.

use std::io;
use std::sync::Mutex;

/// What one `cgroup.kill` write answered, for a removal that is told it and writes no more: `Ok`
/// landed, `Err` carries why it failed.
pub(crate) type KillAnswer = Result<(), String>;

#[derive(Debug, Default)]
enum Written {
    /// No write was made.
    #[default]
    Never,
    /// A write landed: the tree is dying, so waiting for its drain ends.
    Landed,
    /// Every write made failed, the last for this reason.
    Failed(String),
}

/// What the writes of one leaf's `cgroup.kill` answered. A leaf is torn down with one write, so a
/// teardown that finds a write made reads its answer and makes no other. A landed write stays the
/// answer after a later failed one: its kill still bounds the drain.
#[derive(Debug, Default)]
pub(crate) struct KillRecord(Mutex<Written>);

impl KillRecord {
    fn written(&self) -> std::sync::MutexGuard<'_, Written> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records the answer of a write.
    pub(crate) fn record(&self, written: Result<(), &io::Error>) {
        let mut record = self.written();
        match (written, &*record) {
            (Ok(()), _) => *record = Written::Landed,
            (Err(_), Written::Landed) => {}
            (Err(e), _) => *record = Written::Failed(e.to_string()),
        }
    }

    /// Whether a write landed.
    pub(crate) fn landed(&self) -> bool {
        matches!(*self.written(), Written::Landed)
    }

    /// What the writes answered, `None` if none was made: a teardown that finds one makes no other.
    pub(crate) fn answer(&self) -> Option<KillAnswer> {
        match &*self.written() {
            Written::Never => None,
            Written::Landed => Some(Ok(())),
            Written::Failed(why) => Some(Err(why.clone())),
        }
    }

    /// Why the writes failed, if none landed and one failed.
    pub(crate) fn failure(&self) -> Option<String> {
        match &*self.written() {
            Written::Failed(why) => Some(why.clone()),
            _ => None,
        }
    }
}
