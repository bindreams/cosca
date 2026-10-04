//! The elevation shim: a small cosca-controlled executable that an elevation front runs in place of
//! the elevated program, so that cosca can reach the program through a socket.
//!
//! [`protocol`] is the wire format between the two: the shim's argv, its frames to cosca, and
//! cosca's commands to it. [`private_dir`] is the directory that holds the socket.

mod choice;
#[cfg(test)]
pub(crate) mod fixtures;
// Crate-private and not yet called: the `ShimLink` that owns it lands next.
#[allow(dead_code, reason = "its only caller, ShimLink, lands in a later unit")]
pub(crate) mod private_dir;
pub(crate) mod protocol;

#[allow(unused_imports, reason = "no caller yet")]
pub(crate) use choice::ShimChoice;
