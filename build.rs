//! Embeds `testbin/long_path_aware.manifest` in `cosca_testbin_cwd`, and in no other binary.
//!
//! Test-only: the package excludes this file, so a dependent never builds it. `embed-manifest`
//! passes its `LINK.EXE` options to every `[[bin]]` (`rustc-link-arg-bins`), which would make each
//! testbin long-path aware and change how it handles paths, so the same three options go to this
//! one binary instead. Off MSVC the binary gets no manifest, and its tests' precondition check
//! fails.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let root = std::path::PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let manifest = root.join("testbin").join("long_path_aware.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    let target = |key: &str| std::env::var(key).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") != "windows" || target("CARGO_CFG_TARGET_ENV") != "msvc" {
        return;
    }
    for arg in [
        "/MANIFEST:EMBED".to_owned(),
        format!("/MANIFESTINPUT:{}", manifest.display()),
        "/MANIFESTUAC:NO".to_owned(),
    ] {
        println!("cargo:rustc-link-arg-bin=cosca_testbin_cwd={arg}");
    }
}
