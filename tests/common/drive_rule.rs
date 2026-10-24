//! M7's runner: what a child's own `GetFullPathNameW` makes of a drive-relative name, given an
//! environment block and a cwd built here, against what D1 predicts. `cosca_testbin with-env-block`
//! starts the child with exactly the row's block, and the child's `full-path` mode reports.
//!
//! D1 (#173's rule, kept by the untangling plan as `complete` plus `HostOs::drive_base`) completes
//! `X:rest` onto, in order: E, when E is drive-absolute on drive X (`Base`); the child's first
//! `=X:` entry, when it is fully qualified and an existing directory (`Value`); else `X:\` (`Root`).
//! A row prints the arm, the prediction, what the child reported, and whether they agree. It asserts
//! only its preconditions: the child ran in the row's cwd and, where the row says so, saw the
//! row's `=X:` value.
#![cfg(windows)]

use std::process::Command;

/// The child's working directory.
pub enum Cwd {
    /// Passed as `lpCurrentDirectory`.
    Given(String),
    /// Left `NULL`, so the child inherits its launcher's cwd, which is this.
    Inherited(String),
}

impl Cwd {
    fn path(&self) -> &str {
        match self {
            Cwd::Given(p) | Cwd::Inherited(p) => p,
        }
    }
}

/// What the child's own `GetEnvironmentVariableW("=X:")` must return before the call.
pub enum Var {
    /// This value, or unset for `None`: the row's block reached the child as built.
    Is(Option<String>),
    /// Which entry ntdll reads is itself the measurement.
    Recorded,
}

pub struct Row {
    pub key: &'static str,
    pub cwd: Cwd,
    /// The child's whole environment block, in order.
    pub block: Vec<String>,
    /// The drive-relative name given to `GetFullPathNameW`.
    pub name: String,
    /// `Base`, `Value` or `Root`.
    pub arm: &'static str,
    pub predicted: String,
    pub var: Var,
}

/// Replaces each `(from, to)` in order, ignoring ASCII case: Windows reports a directory under
/// several casings.
pub struct Render(pub Vec<(String, String)>);

impl Render {
    pub fn apply(&self, s: &str) -> String {
        self.0
            .iter()
            .fold(s.to_owned(), |s, (from, to)| replace_ignore_case(&s, from, to))
    }
}

fn replace_ignore_case(s: &str, from: &str, to: &str) -> String {
    if from.is_empty() {
        return s.to_owned();
    }
    let (lower, needle) = (s.to_ascii_lowercase(), from.to_ascii_lowercase());
    let mut out = String::new();
    let mut at = 0;
    while let Some(found) = lower[at..].find(&needle) {
        out.push_str(&s[at..at + found]);
        out.push_str(to);
        at += found + needle.len();
    }
    out.push_str(&s[at..]);
    out
}

/// Runs `row` and prints it as `M7 <key> <field>=<value>` lines, rendered by `render` and then
/// `drive`, a case-sensitive `(from, to)` pair so a lowercase drive letter stays visible.
pub fn run(row: &Row, render: &Render, drive: Option<(char, char)>) {
    let mut cmd = Command::new(crate::common::testbin());
    cmd.arg("with-env-block");
    match &row.cwd {
        Cwd::Given(cwd) => {
            cmd.arg("--cwd").arg(cwd);
        }
        Cwd::Inherited(cwd) => {
            cmd.current_dir(cwd);
        }
    }
    cmd.args(&row.block).arg("--").arg("full-path").arg(&row.name);
    let out = crate::common::output_locked(&mut cmd).expect("spawn the launcher");
    let report = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "M7 {}: the probe failed ({}): {report}\n{}",
        row.key,
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let cwd = value(&report, "cwd");
    assert_eq!(
        cwd,
        row.cwd.path(),
        "M7 {}: precondition: the child runs in the row's cwd",
        row.key
    );
    let var = value(&report, "var");
    if let Var::Is(expected) = &row.var {
        let expected = expected.as_deref().unwrap_or("<unset>");
        assert_eq!(
            var, expected,
            "M7 {}: precondition: the child sees the block's =X: value",
            row.key
        );
    }
    let full = value(&report, "full");
    let show = |s: &str| {
        let s = render.apply(s);
        match drive {
            Some((from, to)) => s.replace(&format!("{from}:"), &format!("{to}:")).replace(
                &format!("{}:", from.to_ascii_lowercase()),
                &format!("{}:", to.to_ascii_lowercase()),
            ),
            None => s,
        }
    };
    let k = row.key;
    println!("M7 {k} cwd={}", show(cwd));
    println!(
        "M7 {k} block={:?}",
        row.block.iter().map(|e| show(e)).collect::<Vec<_>>()
    );
    println!("M7 {k} name={}", show(&row.name));
    println!("M7 {k} var={}", show(var));
    println!("M7 {k} arm={}", row.arm);
    println!("M7 {k} predicted={}", show(&row.predicted));
    println!("M7 {k} full={}", show(full));
    println!("M7 {k} var_after={}", show(value(&report, "var_after")));
    println!("M7 {k} agrees={}", full == row.predicted);
}

/// The value of the first `key=` line of `report`; a missing key fails the test.
fn value<'a>(report: &'a str, key: &str) -> &'a str {
    let prefix = format!("{key}=");
    report
        .lines()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("the report has no {key}= line:\n{report}"))
}

/// `path` canonicalised, without the `\\?\` that `canonicalize` adds, so a short (8.3) temp path
/// is spelled long, as the child reports it.
pub fn canonical(path: &std::path::Path) -> String {
    let full = std::fs::canonicalize(path).expect("canonicalize");
    let full = full.to_str().expect("a UTF-8 path");
    full.strip_prefix(r"\\?\")
        .expect("a verbatim canonical path")
        .to_owned()
}

/// A drive letter absent from `GetLogicalDrives`, searching `letters` in order.
pub fn free_drive(letters: impl IntoIterator<Item = u8>) -> char {
    use windows::Win32::Storage::FileSystem::GetLogicalDrives;
    // SAFETY: no arguments; reads the mounted drives.
    let mask = unsafe { GetLogicalDrives() };
    letters
        .into_iter()
        .find(|l| mask & (1 << (l - b'A')) == 0)
        .expect("a free drive letter") as char
}
