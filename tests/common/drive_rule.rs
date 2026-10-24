//! M7's runner: what a child's own `GetFullPathNameW` makes of a drive-relative name, given an
//! environment block and a cwd built here, against what D1 predicts. `cosca_testbin with-env-block`
//! starts the child with exactly the row's block, and the child's `full-path` mode reports.
//!
//! D1, the drive rule (`complete` plus `HostOs::drive_base`), completes `X:rest` onto, in order: the
//! cwd E, when E is drive-absolute on drive X (`Base`); the child's first `=X:` entry, when it is
//! fully qualified and an existing directory (`Value`); else `X:\` (`Root`). A row prints the
//! predicted arm, the arm observed, the prediction, what the child reported, and whether they
//! agree. It asserts only its preconditions: the child ran in the row's cwd and, where the row
//! says so, saw the row's `=X:` value.
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
    /// Which entry the child reads is itself the measurement, so only: one of the block's `=X:` values.
    Recorded,
}

/// The arm D1 predicts.
pub enum Arm {
    /// The cwd.
    Base,
    /// This `=X:` value.
    Value(String),
    /// The name's drive root.
    Root,
}

impl Arm {
    fn name(&self) -> &'static str {
        match self {
            Arm::Base => "Base",
            Arm::Value(_) => "Value",
            Arm::Root => "Root",
        }
    }
}

pub struct Row {
    pub key: &'static str,
    pub cwd: Cwd,
    /// The child's whole environment block, in order.
    pub block: Vec<String>,
    /// The drive-relative name given to `GetFullPathNameW`.
    pub name: String,
    pub arm: Arm,
    pub var: Var,
}

impl Row {
    /// D1's result for the name: its arm's directory joined with the name past its drive, `.` and
    /// `..` resolved without going above the root, trailing dots of a component dropped.
    fn predicted(&self) -> String {
        let mut chars = self.name.chars();
        let drive = chars.next().expect("a drive-relative name");
        assert_eq!(chars.next(), Some(':'), "{}: a drive-relative name", self.key);
        let base = match &self.arm {
            Arm::Base => self.cwd.path().to_owned(),
            Arm::Value(value) => value.clone(),
            Arm::Root => format!(r"{drive}:\"),
        };
        let (root, tail) = base.split_at(root_len(&base));
        let mut parts: Vec<&str> = tail.split('\\').filter(|c| !c.is_empty()).collect();
        for component in chars.as_str().split('\\') {
            match component {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                c => parts.push(c.trim_end_matches('.')),
            }
        }
        format!("{root}{}", parts.join("\\"))
    }
}

/// The byte length of `path`'s root, with its separator: `X:\`, `\\?\X:\` or `\\server\share\`.
fn root_len(path: &str) -> usize {
    if let Some(rest) = path.strip_prefix(r"\\?\") {
        return path.len() - rest.len() + drive_root_len(rest);
    }
    if let Some(rest) = path.strip_prefix(r"\\") {
        let mut seps = rest.match_indices('\\').map(|(i, _)| i);
        let end = seps.nth(1).map_or(rest.len(), |i| i + 1);
        return 2 + end;
    }
    drive_root_len(path)
}

/// The byte length of the `X:\` that `path` starts with, or 0.
fn drive_root_len(path: &str) -> usize {
    let mut chars = path.chars();
    match (chars.next(), chars.next(), chars.next()) {
        (Some(c), Some(':'), Some('\\')) => c.len_utf8() + 2,
        _ => 0,
    }
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
/// `drives`: each `(letter, placeholder)` pair prints the drive `letter:` as `<P>:`, or `<p>:` for a
/// lowercase letter, so two drives never print alike and a lowercase one stays visible.
pub fn run(row: &Row, render: &Render, drives: &[(char, char)]) {
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
    match &row.var {
        Var::Is(expected) => assert_eq!(
            var,
            expected.as_deref().unwrap_or("<unset>"),
            "M7 {}: precondition: the child sees the block's =X: value",
            row.key
        ),
        Var::Recorded => assert!(
            row.block
                .iter()
                .filter_map(|e| e.strip_prefix('=')?.split_once('='))
                .any(|(_, v)| v == var),
            "M7 {}: precondition: the child sees one of the block's =X: values, not {var:?}",
            row.key
        ),
    }
    let full = value(&report, "full");
    let var_after = value(&report, "var_after");
    let observed = observed_arm(row.cwd.path(), &row.name, var, full);
    let predicted = row.predicted();
    let show = |s: &str| render_drives(&render.apply(s), drives);
    let k = row.key;
    println!("M7 {k} cwd={}", show(cwd));
    println!(
        "M7 {k} block={:?}",
        row.block.iter().map(|e| show(e)).collect::<Vec<_>>()
    );
    println!("M7 {k} name={}", show(&row.name));
    println!("M7 {k} var={}", show(var));
    println!("M7 {k} predicted_arm={}", row.arm.name());
    println!("M7 {k} observed_arm={observed}");
    println!("M7 {k} predicted={}", show(&predicted));
    println!("M7 {k} full={}", show(full));
    println!("M7 {k} var_after={}", show(var_after));
    println!("M7 {k} agrees={}", full == predicted);
}

/// Prints each `letter:` of `drives` as its placeholder, in one pass so a placeholder is never
/// rewritten. A letter counts only where it does not end a word.
fn render_drives(s: &str, drives: &[(char, char)]) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let starts_word = i == 0 || !chars[i - 1].is_alphanumeric();
        let placeholder = drives
            .iter()
            .find(|(letter, _)| c.is_ascii_alphabetic() && letter.eq_ignore_ascii_case(&c))
            .filter(|_| starts_word && chars.get(i + 1) == Some(&':'));
        if let Some((_, name)) = placeholder {
            let name = if c.is_ascii_lowercase() {
                name.to_ascii_lowercase()
            } else {
                name.to_ascii_uppercase()
            };
            out.push_str(&format!("<{name}>:"));
            i += 2;
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// The arm the child's result took, from its report: `Error` when `GetFullPathNameW` failed;
/// `Base` when the name's drive is the drive of a drive-absolute `cwd` and `full` is under the cwd;
/// `Value` when `var` is fully qualified, an existing directory, and `full` is under it; `Root` when
/// `full` is not under the cwd and starts with the name's drive root; else `Other`. Case-insensitive
/// for ASCII only.
fn observed_arm(cwd: &str, name: &str, var: &str, full: &str) -> &'static str {
    let under = |path: &str, dir: &str| starts_with_ignore_case(path, &format!("{}\\", dir.trim_end_matches('\\')));
    if full.starts_with("err=") {
        return "Error";
    }
    let name_drive = name.chars().next().expect("a drive-relative name");
    let cwd_drive = match cwd.chars().next() {
        Some(c) if c.is_ascii_alphabetic() && drive_root_len(cwd) > 0 => Some(c),
        _ => None,
    };
    let fully_qualified = drive_root_len(var) > 0 || (var.starts_with(r"\\") && !var.starts_with(r"\\.\"));
    if cwd_drive.is_some_and(|c| c.eq_ignore_ascii_case(&name_drive)) && under(full, cwd) {
        "Base"
    } else if fully_qualified && std::path::Path::new(var).is_dir() && under(full, var) {
        "Value"
    } else if !under(full, cwd) && starts_with_ignore_case(full, &format!("{name_drive}:\\")) {
        "Root"
    } else {
        "Other"
    }
}

fn starts_with_ignore_case(s: &str, prefix: &str) -> bool {
    s.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase())
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
    let path = full.strip_prefix(r"\\?\").expect("a verbatim canonical path");
    assert!(
        path.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) && drive_root_len(path) > 0,
        r"precondition: the temp directory's canonical path {path:?} is drive-absolute (`X:\`), as the rows build on it"
    );
    path.to_owned()
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
