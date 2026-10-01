//! The environment block a probe hands a child under another account or a lowered token.

use super::{env_block_from, skuld_db_dir};
use std::ffi::OsString;

/// The `KEY=value` entries of a NUL-separated, double-NUL-terminated UTF-16 block.
fn entries(block: &[u16]) -> Vec<String> {
    block
        .split(|&u| u == 0)
        .filter(|e| !e.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

fn inherited(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|&(k, v)| (k.into(), v.into())).collect()
}

#[skuld::test]
fn a_skuld_db_dir_passed_in_extra_reaches_the_block() {
    let dir = std::path::Path::new(r"C:\probe\dir");
    let block = env_block_from(inherited(&[("PATH", "p")]), &[skuld_db_dir(dir)]);
    assert!(
        entries(&block).contains(&r"SKULD_DB_DIR=C:\probe\dir".to_owned()),
        "{:?}",
        entries(&block)
    );
}

/// The parent's directory belongs to the parent's account: a child under another one cannot write it.
#[skuld::test]
fn an_inherited_skuld_db_dir_is_not_forwarded() {
    let block = env_block_from(inherited(&[("PATH", "p"), ("SKULD_DB_DIR", r"C:\parent")]), &[]);
    let entries = entries(&block);
    assert!(entries.iter().all(|e| !e.starts_with("SKULD_DB_DIR=")), "{entries:?}");
}

#[skuld::test]
fn extra_overrides_an_inherited_skuld_db_dir() {
    let dir = std::path::Path::new(r"C:\probe\dir");
    let block = env_block_from(inherited(&[("SKULD_DB_DIR", r"C:\parent")]), &[skuld_db_dir(dir)]);
    let db: Vec<_> = entries(&block)
        .into_iter()
        .filter(|e| e.starts_with("SKULD_DB_DIR="))
        .collect();
    assert_eq!(db, [r"SKULD_DB_DIR=C:\probe\dir"]);
}
