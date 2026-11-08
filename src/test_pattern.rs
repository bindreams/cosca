//! The byte stream tests send through a pipe, so that a wrong offset, a reordered or repeated
//! chunk, or a stale buffer tail shows in an exact comparison, which a run of one repeated byte
//! cannot.
//!
//! Also mounted by `#[path]` into `tests/common`, so it names nothing of its crate.

/// Byte `i` of the stream every test sends: a period coprime to every power of two, so a chunk that
/// lost or repeated bytes cannot sum to the right total by accident.
pub fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

/// The first `len` bytes of the stream.
pub fn pattern_bytes(len: usize) -> Vec<u8> {
    (0..len).map(pattern).collect()
}
