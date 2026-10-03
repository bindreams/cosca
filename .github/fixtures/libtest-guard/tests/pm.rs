// An error only code generation sees; this target has no other case, so a failure here is not masked by a finding.
fn main() {}

#[cfg(feature = "post_mono")] #[no_mangle] pub extern "C" fn post_mono() { struct S<T>(T); impl<T> S<T> { const OK: () = assert!(core::mem::size_of::<T>() == 0); } let () = S::<u8>::OK; }
