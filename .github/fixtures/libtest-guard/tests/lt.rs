// The default harness: libtest runs `#[test]` here, so only the manifest check concerns this target.
#![allow(dead_code)]
#[path = "../src/shared.rs"]
mod shared;
#[test]
fn ok() {}
