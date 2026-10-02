//! Shared test helpers.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::modtree::Source;

/// An in-memory tree; paths are keyed as written (all absolute-looking, `/t/...`).
#[derive(Default, Clone)]
pub struct MemSource(pub BTreeMap<PathBuf, String>);

impl MemSource {
    pub fn new(files: &[(&str, &str)]) -> Self {
        Self(files.iter().map(|(p, s)| (PathBuf::from(p), (*s).to_owned())).collect())
    }
}

impl Source for MemSource {
    fn read(&self, path: &Path) -> Result<Option<String>> {
        Ok(self.0.get(path).cloned())
    }
}

pub fn paths(files: &[crate::modtree::ParsedFile]) -> Vec<String> {
    let mut v: Vec<String> = files.iter().map(|f| f.path.to_string_lossy().into_owned()).collect();
    v.sort();
    v
}
