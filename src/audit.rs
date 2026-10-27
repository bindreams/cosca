//! Spike: the audit hook's compile switch. Holds nothing yet.

/// `true` when the crate was built with the hidden `__test_hooks` feature.
pub fn enabled() -> bool {
    cfg!(feature = "__test_hooks")
}
