//! The elevation shim: a small cosca-controlled executable that an elevation front runs in place of
//! the elevated program, so that cosca can reach the program through a socket.
//!
//! [`protocol`] is the wire format between the two: the shim's argv, its frames to cosca, and
//! cosca's commands to it. [`private_dir`] is the directory that holds the socket, and [`link`] is
//! cosca's end of the channel.

mod choice;
#[cfg(test)]
pub(crate) mod fixtures;
pub(crate) mod fork_guard;
pub(crate) mod link;
pub(crate) mod private_dir;
pub(crate) mod protocol;

#[allow(unused_imports, reason = "no caller yet")]
pub(crate) use choice::ShimChoice;
