// Each case is one line, so a diagnostic's line is the line of its `fn`/`emit!` below.
#![allow(dead_code, unused_imports)]
#![cfg_attr(all(test, feature = "crate_allow"), allow(clippy::all))]
fn main() {}

#[cfg(feature = "plain")] #[test] fn plain() {}
#[cfg(feature = "tokio_test")] #[tokio::test] async fn tokio_test() {}
#[cfg(feature = "prelude_path")] #[core::prelude::v1::test] fn prelude_path() {}
#[cfg(feature = "cfg_attr_test")] #[cfg_attr(all(), test)] fn cfg_attr_test() {}
#[cfg(feature = "renamed")] use core::prelude::v1::test as t;
#[cfg(feature = "renamed")] #[t] fn renamed() {}
#[cfg(feature = "macro_rules")] macro_rules! emit { () => { #[test] fn from_macro() {} }; }
#[cfg(feature = "macro_rules")] emit!();
#[cfg(feature = "shared")] #[path = "../src/shared.rs"] mod shared;
#[cfg(all(feature = "release_only", not(debug_assertions)))] #[tokio::test] async fn release_only() {}
#[cfg(all(feature = "os_linux", target_os = "linux"))] #[tokio::test] async fn os_linux() {}
#[cfg(all(feature = "os_macos", target_os = "macos"))] #[tokio::test] async fn os_macos() {}
#[cfg(all(feature = "os_windows", windows))] #[tokio::test] async fn os_windows() {}
#[cfg(all(feature = "ps_a", not(feature = "ps_b")))] #[tokio::test] async fn ps_only_a() {}
#[cfg(all(feature = "ps_b", not(feature = "ps_a")))] #[tokio::test] async fn ps_only_b() {}
#[cfg(all(not(any(feature = "plain", feature = "tokio_test", feature = "prelude_path", feature = "cfg_attr_test", feature = "renamed", feature = "macro_rules", feature = "shared", feature = "release_only", feature = "os_linux", feature = "os_macos", feature = "os_windows", feature = "bin_test_false", feature = "ps_a", feature = "ps_b", feature = "crate_allow", feature = "type_error", feature = "arch_x86_64", feature = "arch_aarch64", feature = "quiet", feature = "post_mono"))))] #[tokio::test] async fn ps_none() {}
#[cfg(all(feature = "crate_allow"))] #[test] fn crate_allowed() {}
#[cfg(all(feature = "arch_x86_64", target_arch = "x86_64"))] #[tokio::test] async fn arch_x86_64() {}
#[cfg(all(feature = "arch_aarch64", target_arch = "aarch64"))] #[tokio::test] async fn arch_aarch64() {}
#[cfg(feature = "post_mono")] #[no_mangle] pub extern "C" fn post_mono_it() { struct S<T>(T); impl<T> S<T> { const OK: () = assert!(core::mem::size_of::<T>() == 0); } let () = S::<u8>::OK; }
