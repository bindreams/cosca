//! What the single-backend measurement modes share: rendering a spawn's outcome as one `key=value`
//! line, with the directories they made replaced by short names so runs compare.

/// Replaces each `(from, to)` in `s`, in order. Matching ignores ASCII case: Windows reports one
/// directory under several casings.
pub(crate) struct Render(pub(crate) Vec<(String, String)>);

impl Render {
    pub(crate) fn apply(&self, s: &str) -> String {
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

/// The string a Win32 call that fills a UTF-16 buffer returns. When `f` reports a size past the
/// buffer, it retries with a buffer of that size, until the result fits. `Err` is the OS error
/// code of a call that returned 0.
pub(crate) fn wide_string(mut f: impl FnMut(&mut [u16]) -> u32) -> Result<String, i32> {
    let mut buf = vec![0u16; 1024];
    loop {
        let n = f(&mut buf) as usize;
        if n == 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));
        }
        if n < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n]));
        }
        buf.resize(n, 0);
    }
}

/// An I/O error as `err=<code>`, or `err(<kind>)` when it carries no OS code.
pub(crate) fn io_error(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(code) => format!("err={code}"),
        None => format!("err({:?})", e.kind()),
    }
}

/// A cosca error: an I/O error as [`io_error`] renders it, any other by its variant.
pub(crate) fn cosca_error(e: &cosca::error::Error) -> String {
    use cosca::error::Error;
    match e {
        Error::Io(io) => io_error(io),
        Error::Unsupported { .. } => "err(Unsupported)".to_owned(),
        Error::Containment { .. } => "err(Containment)".to_owned(),
        Error::Quote(_) => "err(Quote)".to_owned(),
        other => format!("err({other})"),
    }
}

/// A finished child: `ok,` then its `keys=` lines, or `exit=<code>` for a failure.
pub(crate) fn finished(success: bool, code: Option<i32>, stdout: &[u8], keys: &[&str], render: &Render) -> String {
    if !success {
        return format!("exit={code:?}");
    }
    let stdout = String::from_utf8_lossy(stdout);
    let found: Vec<String> = keys
        .iter()
        .map(|key| {
            stdout
                .lines()
                .find(|line| line.starts_with(&format!("{key}=")))
                .map_or_else(|| format!("no {key}= line"), |line| render.apply(line))
        })
        .collect();
    format!("ok,{}", found.join(","))
}

/// [`finished`] for a `std::process::Command` run to completion with its stdout captured.
pub(crate) fn std_run(cmd: &mut std::process::Command, keys: &[&str], render: &Render) -> String {
    #[allow(
        clippy::disallowed_methods,
        reason = "no other thread of this process forks: these modes start none, and the crate's helper threads only wait"
    )]
    let out = cmd.output();
    match out {
        Ok(out) => finished(out.status.success(), out.status.code(), &out.stdout, keys, render),
        Err(e) => io_error(&e),
    }
}

/// [`finished`] for a `cosca::Command` run to completion with its stdout captured.
pub(crate) fn cosca_run(cmd: &mut cosca::Command, keys: &[&str], render: &Render) -> String {
    match cmd.output() {
        Ok(out) => finished(out.status.success(), out.status.code(), &out.stdout, keys, render),
        Err(e) => cosca_error(&e),
    }
}

/// A `std::process::Command`'s stdout, or why it has none.
pub(crate) fn std_stdout(cmd: &mut std::process::Command) -> Result<Vec<u8>, String> {
    #[allow(
        clippy::disallowed_methods,
        reason = "no other thread of this process forks: these modes start none, and the crate's helper threads only wait"
    )]
    let out = cmd.output();
    match out {
        Ok(out) if out.status.success() => Ok(out.stdout),
        Ok(out) => Err(format!("exit={:?}", out.status.code())),
        Err(e) => Err(io_error(&e)),
    }
}

/// A `cosca::Command`'s stdout, or why it has none.
pub(crate) fn cosca_stdout(cmd: &mut cosca::Command) -> Result<Vec<u8>, String> {
    match cmd.output() {
        Ok(out) if out.status.success() => Ok(out.stdout),
        Ok(out) => Err(format!("exit={:?}", out.status.code())),
        Err(e) => Err(cosca_error(&e)),
    }
}

/// A new directory under `base` whose path is exactly `units` UTF-16 units long, made of
/// components of at most 100 units.
pub(crate) fn dir_of_len(base: &std::path::Path, units: usize) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStrExt;
    let len = |p: &std::path::Path| p.as_os_str().encode_wide().count();
    assert!(
        len(base) + 2 <= units,
        "{base:?} is already {} units, past {units}",
        len(base)
    );
    let mut dir = base.to_path_buf();
    while len(&dir) < units {
        let room = units - len(&dir) - 1;
        // Never leave a single unit, which a separator alone would take.
        let take = if room > 100 && room - 100 < 2 {
            room - 2
        } else {
            room.min(100)
        };
        dir.push("a".repeat(take));
    }
    assert_eq!(len(&dir), units);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create {dir:?}: {e}"));
    dir
}
