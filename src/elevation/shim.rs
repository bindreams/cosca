//! The elevation shim (plan F): a small cosca-controlled executable that an elevation front runs
//! in place of the elevated program, so that cosca can reach the program through a socket.
//!
//! Only the wire protocol lives here so far; its two directions are [`protocol`].

pub(crate) mod protocol;
