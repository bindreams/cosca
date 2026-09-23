//! The raw and std Windows backends hand a child the same environment block — names, values and
//! order — for the same inherited environment and env ops.
#![cfg(windows)]
// See `src/lib.rs`'s header for why: this integration test crate is its own clippy-linted
// crate root, so it needs its own copy of the deny.
#![deny(clippy::allow_attributes_without_reason)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

#[path = "common/mod.rs"]
mod common;

/// The environment every intermediate process starts with, and so the one both backends inherit.
const INHERITED: [(&str, &str); 4] = [("Path", "inh"), ("SS", "inh"), ("Foo", "inh"), ("zz", "inh")];

/// The block a child spawned through `backend` receives.
///
/// The inherited environment is controlled without touching this process's own: an intermediate
/// `cosca_testbin` is started with exactly [`INHERITED`] plus `SystemRoot` (set on the
/// intermediate's `Command`, so nothing here mutates this process's environment and no test can
/// race on it). The intermediate never changes its environment, so both backends' inherited base
/// is identical by construction; it then spawns `dump-env-block` through `backend` with `ops`.
fn child_block(backend: &str, ops: &[String]) -> Vec<OsString> {
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot");
    let mut cmd = std::process::Command::new(common::testbin());
    cmd.env_clear()
        .envs(INHERITED)
        .env("SystemRoot", system_root)
        .arg("spawn-dump-env-block")
        .arg(backend)
        .args(ops);
    let out = common::output_locked(&mut cmd).expect("spawn intermediate");
    assert!(
        out.status.success(),
        "intermediate failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_block(&out.stdout)
}

/// `dump-env-block`'s output: one entry per line, each UTF-16 unit as four hex digits.
fn parse_block(stdout: &[u8]) -> Vec<OsString> {
    std::str::from_utf8(stdout)
        .unwrap()
        .lines()
        .map(|hex| {
            let units: Vec<u16> = (0..hex.len())
                .step_by(4)
                .map(|i| u16::from_str_radix(&hex[i..i + 4], 16).unwrap())
                .collect();
            OsString::from_wide(&units)
        })
        .collect()
}

#[test]
fn raw_and_std_backends_give_a_child_the_same_environment_block() {
    let system_root = std::env::var("SystemRoot").expect("SystemRoot");
    let set_root = format!("set:SystemRoot={system_root}");
    // Each case: the ops, and entries std's block must contain (a control that the case exercises
    // what it names).
    let cases: [(Vec<&str>, Vec<&str>); 6] = [
        (vec!["set:PATH=x"], vec!["Path=x"]),
        (vec!["remove:PATH", "set:pAth=x"], vec!["Path=x"]),
        (vec!["set:ß=x"], vec!["SS=inh", "ß=x"]),
        (
            vec!["set:foo=1", "set:FOO=2", "set:New=1", "set:NEW=2"],
            vec!["Foo=2", "New=2"],
        ),
        (vec!["remove:ss", "set:ﬁ=1", "set:FI=2"], vec!["FI=2", "ﬁ=1"]),
        (
            vec![
                "clear", &set_root, "set:a=1", "remove:A", "set:A=2", "set:ß=x", "set:SS=y",
            ],
            vec!["A=2", "SS=y", "ß=x"],
        ),
    ];
    for (ops, expect) in cases {
        let ops: Vec<String> = ops.into_iter().map(String::from).collect();
        let std = child_block("std", &ops);
        for entry in expect {
            assert!(
                std.iter().any(|e| e == entry),
                "{ops:?}: std block lacks {entry:?}: {std:?}"
            );
        }
        assert_eq!(child_block("raw", &ops), std, "{ops:?}");
    }
}

/// With no ops the raw backend passes this process's block on byte for byte, as std's NULL block
/// does: unsorted entries and an `EnvKey`-equal duplicate reach both children unchanged. The
/// intermediate's block is built by `spawn-with-env-block`, since std's `Command` would clean it.
/// No `=`-less entry: `CreateProcessW` refuses one (see `create_process_block_acceptance`), so no
/// parent can hand its child such a block.
#[test]
fn with_no_ops_both_backends_pass_the_parent_block_verbatim() {
    let system_root = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let entries = [system_root.as_str(), "Path=a", "zz=1", "PATH=b", "ß=1", "SS=2"];
    let run = |backend: &str| {
        let mut cmd = std::process::Command::new(common::testbin());
        cmd.arg("spawn-with-env-block").arg(backend).args(entries);
        let out = common::output_locked(&mut cmd).expect("spawn");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        parse_block(&out.stdout)
    };
    let std = run("std");
    assert_eq!(
        std,
        as_the_os_delivers(&entries),
        "std's child is the control: it must see the parent block, plus only what the OS adds"
    );
    assert_eq!(run("raw"), std);
}

/// `entries` as a child receives them from the OS. On ARM64 Windows the OS prepends
/// `PROCESSOR_ARCHITECTURE=ARM64` to a child's block that lacks it; on x64 it adds nothing.
fn as_the_os_delivers(entries: &[&str]) -> Vec<OsString> {
    let mut want: Vec<OsString> = entries.iter().map(OsString::from).collect();
    let has_arch = entries
        .iter()
        .any(|e| e.to_ascii_uppercase().starts_with("PROCESSOR_ARCHITECTURE="));
    if cfg!(target_arch = "aarch64") && !has_arch {
        want.insert(0, "PROCESSOR_ARCHITECTURE=ARM64".into());
    }
    want
}

/// A contained spawn's environment is the snapshot its containment decision was read from, on both
/// backends. std cannot pass a block verbatim, so both rebuild it: the duplicate `PATH` collapses to
/// one entry, first name and last value. The inherited marker makes the spawn nested, so no marker
/// op is added and no ops at all are recorded.
#[test]
fn a_contained_child_gets_the_rebuilt_snapshot_on_both_backends() {
    let system_root = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let entries = [system_root.as_str(), "Path=a", "zz=1", "PATH=b", "__COSCA_GROUP_ROOT=1"];
    let run = |dump_args: &str| {
        let mut cmd = std::process::Command::new(common::testbin());
        cmd.arg("spawn-with-env-block").arg(dump_args).args(entries);
        let out = common::output_locked(&mut cmd).expect("spawn");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        parse_block(&out.stdout)
    };
    let std = run("std contain");
    let paths: Vec<&OsString> = std
        .iter()
        .filter(|e| e.to_string_lossy().to_ascii_uppercase().starts_with("PATH="))
        .collect();
    assert_eq!(paths, [&OsString::from("Path=b")], "{std:?}");
    assert_eq!(run("raw contain"), std);
}

/// What `CreateProcessW` accepts as a child's block, measured: which parent blocks can exist.
#[test]
fn create_process_block_acceptance() {
    let system_root = format!("SystemRoot={}", std::env::var("SystemRoot").expect("SystemRoot"));
    let probe = |extra: &[&str]| {
        let mut cmd = std::process::Command::new(common::testbin());
        cmd.arg("try-env-block").arg(&system_root).args(extra);
        let out = common::output_locked(&mut cmd).expect("spawn");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    };
    assert_eq!(probe(&[]), "ok", "control");
    assert_eq!(probe(&["Path=a", "zz=1", "PATH=b"]), "ok", "duplicates, unsorted");
    assert_eq!(probe(&["=C:=C:\\x"]), "ok", "a drive-cwd entry");
    assert_eq!(probe(&["JUNK"]), "err=87", "an entry with no `=`");
}
