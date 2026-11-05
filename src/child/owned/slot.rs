//! [`ChildSlot`]: an [`OwnedChild`] its holder can give up once.

use std::ops::{Deref, DerefMut};

use super::OwnedChild;

/// An [`OwnedChild`] that a holder with a `Drop` can still move out: a field of such a type cannot
/// be moved (E0509), so [`take`](Self::take) is the one way out. [`Child`](crate::Child) and
/// [`Unreaped`](crate::Unreaped) hold their child in one.
///
/// It derefs to the child until taken. Using it after is a contract violation and panics: only a
/// method that consumes the holder takes it.
#[derive(Debug)]
pub(crate) struct ChildSlot(Option<OwnedChild>);

impl ChildSlot {
    pub(crate) fn new(child: OwnedChild) -> ChildSlot {
        ChildSlot(Some(child))
    }

    /// The child, once; `None` after.
    pub(crate) fn take(&mut self) -> Option<OwnedChild> {
        self.0.take()
    }
}

impl Deref for ChildSlot {
    type Target = OwnedChild;

    fn deref(&self) -> &OwnedChild {
        self.0.as_ref().expect("the child was taken out of its slot")
    }
}

impl DerefMut for ChildSlot {
    fn deref_mut(&mut self) -> &mut OwnedChild {
        self.0.as_mut().expect("the child was taken out of its slot")
    }
}
