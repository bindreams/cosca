//! [`ChildEnd`] on Windows: a handle the child receives, or none.

use std::fs::File;
use std::io::{PipeReader, PipeWriter};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::process::Stdio;

/// A child-side handle. It is absent when the parent's matching std handle is null (a GUI process's
/// or a service's), or when it is a dup of such an end: the child gets null there.
///
/// `std` allows a null `OwnedHandle`, but dropping one calls `CloseHandle(NULL)`, which raises an
/// invalid-handle exception under a debugger or Application Verifier. An absent end holds no
/// `OwnedHandle`, so dropping it closes nothing.
pub(crate) struct ChildEnd(Option<OwnedHandle>);

impl ChildEnd {
    pub(crate) fn absent() -> ChildEnd {
        ChildEnd(None)
    }

    /// A duplicate of this end: absent for an absent end.
    pub(crate) fn try_clone(&self) -> std::io::Result<ChildEnd> {
        self.0.as_ref().map(OwnedHandle::try_clone).transpose().map(ChildEnd)
    }
}

impl From<OwnedHandle> for ChildEnd {
    fn from(h: OwnedHandle) -> ChildEnd {
        if h.as_raw_handle().is_null() {
            // Nothing to close.
            std::mem::forget(h);
            return ChildEnd(None);
        }
        ChildEnd(Some(h))
    }
}

impl From<PipeReader> for ChildEnd {
    fn from(p: PipeReader) -> ChildEnd {
        ChildEnd(Some(p.into()))
    }
}

impl From<PipeWriter> for ChildEnd {
    fn from(p: PipeWriter) -> ChildEnd {
        ChildEnd(Some(p.into()))
    }
}

impl From<File> for ChildEnd {
    fn from(f: File) -> ChildEnd {
        ChildEnd(Some(f.into()))
    }
}

/// Null for an absent end.
impl AsRawHandle for ChildEnd {
    fn as_raw_handle(&self) -> RawHandle {
        self.0.as_ref().map_or(std::ptr::null_mut(), AsRawHandle::as_raw_handle)
    }
}

/// For `std::process::Command`, which takes the end and closes it. An absent end becomes the null
/// `OwnedHandle` that `std` accepts and itself produces for a null std handle; `std` drops it.
impl From<ChildEnd> for Stdio {
    fn from(end: ChildEnd) -> Stdio {
        match end.0 {
            Some(h) => Stdio::from(h),
            // SAFETY: a null handle owns nothing; `std` documents that `OwnedHandle` may be null.
            None => Stdio::from(unsafe { OwnedHandle::from_raw_handle(std::ptr::null_mut()) }),
        }
    }
}
