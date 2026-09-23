use super::*;

use windows::Win32::Foundation::UNICODE_STRING;

/// A block holding `entries` in order, as `GetEnvironmentStringsW` lays one out.
pub(crate) fn snapshot_of(entries: &[&str]) -> EnvSnapshot {
    let mut block: Vec<u16> = entries.iter().flat_map(|e| e.encode_utf16().chain([0])).collect();
    block.push(0);
    EnvSnapshot::from_block(block)
}

/// Duplicates, an entry with no `=`, and a drive-cwd entry whose name starts with `=`.
const MESSY: [&str; 6] = ["Path=a", "JUNK", "PATH=b", "=C:=C:\\x", "ß=1", "SS=2"];

#[test]
fn vars_parse_the_block_as_vars_os_does() {
    let got: Vec<(OsString, OsString)> = snapshot_of(&MESSY).vars().collect();
    let want: Vec<(OsString, OsString)> = [("Path", "a"), ("PATH", "b"), ("=C:", "C:\\x"), ("ß", "1"), ("SS", "2")]
        .iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    assert_eq!(got, want);
}

#[test]
fn an_empty_block_is_a_double_nul() {
    assert_eq!(EnvSnapshot::from_block(vec![0]).block(), [0, 0]);
    assert_eq!(snapshot_of(&[]).vars().count(), 0);
}

#[test]
fn read_copies_this_process_block() {
    let snapshot = EnvSnapshot::read().unwrap();
    assert!(snapshot.block().ends_with(&[0, 0]));
    let ours: Vec<_> = snapshot.vars().collect();
    let std: Vec<_> = std::env::vars_os().collect();
    assert_eq!(ours, std);
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn RtlQueryEnvironmentVariable_U(
        environment: *const u16,
        name: *const UNICODE_STRING,
        value: *mut UNICODE_STRING,
    ) -> i32;
}

/// What ntdll's own lookup (the one `GetEnvironmentVariableW` makes) reads from `block`.
fn ntdll_var(block: &[u16], name: &str) -> Option<OsString> {
    let mut name: Vec<u16> = name.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: windows::core::PWSTR(name.as_mut_ptr()),
    };
    let mut buf = vec![0u16; 4096];
    let mut value = UNICODE_STRING {
        Length: 0,
        MaximumLength: (buf.len() * 2) as u16 - 2,
        Buffer: windows::core::PWSTR(buf.as_mut_ptr()),
    };
    // SAFETY: `block` is double-NUL terminated; both strings point at live buffers of the stated
    // byte lengths.
    let status = unsafe { RtlQueryEnvironmentVariable_U(block.as_ptr(), &name, &mut value) };
    const STATUS_VARIABLE_NOT_FOUND: i32 = 0xC000_0100_u32 as i32;
    match status {
        0 => Some(OsString::from_wide(&buf[..usize::from(value.Length) / 2])),
        STATUS_VARIABLE_NOT_FOUND => None,
        other => panic!("RtlQueryEnvironmentVariable_U({name:?}) returned {other:#x}"),
    }
}

/// `var` picks the entry ntdll picks: the first match, names split as ntdll splits them.
#[test]
fn var_matches_ntdll() {
    let snapshot = snapshot_of(&MESSY);
    for name in ["PATH", "path", "Path", "JUNK", "=C:", "ß", "SS", "ss", "s", "K", "a=b"] {
        assert_eq!(
            snapshot.var(OsStr::new(name)),
            ntdll_var(snapshot.block(), name),
            "{name:?}"
        );
    }
    assert_eq!(snapshot.var(OsStr::new("PATH")), Some("a".into()));
}
