//! Tests for `pure.rs`, run on every host by `windows_path_logic`. They check the canary's own
//! logic, not the platform.

use super::pure::*;

#[test]
fn verbatim_spelling_of_each_prefix() {
    assert_eq!(verbatim_spelling(r"C:\a\b"), r"\\?\C:\a\b");
    assert_eq!(verbatim_spelling(r"\\?\C:\a"), r"\\?\C:\a");
    assert_eq!(verbatim_spelling(r"\\srv\share\a"), r"\\?\UNC\srv\share\a");
    assert_eq!(verbatim_spelling(r"\\.\C:\a"), r"\\?\C:\a");
    assert_eq!(verbatim_spelling(r"\??\C:\a"), r"\??\C:\a");
}

#[test]
fn pop_past_expectation_is_the_parent_or_the_root_itself() {
    assert_eq!(pop_past_expectation(r"D:\a\b"), r"D:\a");
    assert_eq!(pop_past_expectation(r"D:\a"), "D:");
    assert_eq!(pop_past_expectation("C:"), "C:");
    assert_eq!(pop_past_expectation(r"C:\"), "C:");
    assert_eq!(pop_past_expectation(r"\\srv\share"), r"\\srv\share");
    assert_eq!(pop_past_expectation(r"\\srv\share\a"), r"\\srv\share");
    assert_eq!(pop_past_expectation(r"\\.\C:\x"), r"\\.\C:");
    assert_eq!(pop_past_expectation(r"\\.\C:"), r"\\.");
}

#[test]
fn rooted_prefix_is_the_drive_or_the_share() {
    assert_eq!(rooted_prefix(r"D:\a\b").as_deref(), Some("D:"));
    assert_eq!(rooted_prefix(r"\\srv\share\a").as_deref(), Some(r"\\srv\share"));
    assert_eq!(rooted_prefix(r"\\srv\share").as_deref(), Some(r"\\srv\share"));
    assert_eq!(
        rooted_prefix(r"\\?\UNC\srv\share\a").as_deref(),
        Some(r"\\?\UNC\srv\share")
    );
    assert_eq!(rooted_prefix(r"\\?\C:\a").as_deref(), Some(r"\\?\C:"));
    assert_eq!(rooted_prefix(r"\\.\C:\a").as_deref(), Some(r"\\."));
    assert_eq!(rooted_prefix(r"a\b"), None);
}

#[test]
fn compare_across_roots_maps_the_root_in_errors_too() {
    let (e, n) = (r"T:\edir", r"T:\ndir");
    let same_err = compare_across_roots(
        &Err(format!("GetFullPathNameW({e:?}) failed")),
        &Err(format!("GetFullPathNameW({n:?}) failed")),
        e,
        n,
    );
    assert_eq!(same_err, "identical");
    assert_eq!(
        compare_across_roots(&Ok(format!(r"{e}\x")), &Ok(format!(r"{n}\x")), e, n),
        "identical"
    );
    assert!(compare_across_roots(&Ok(format!(r"{e}\x")), &Err("boom".into()), e, n).starts_with("DIFFERS"));
}

/// A fake `RegGetValueW` whose value is `value`: `ERROR_MORE_DATA` with the needed size while the
/// buffer is short, else the value plus a nul.
fn fake_reg(value: &[u16]) -> impl FnMut(&mut [u16], &mut u32) -> u32 + '_ {
    move |buf, bytes| {
        let need = (value.len() + 1) * 2;
        if (*bytes as usize) < need {
            *bytes = need as u32;
            return ERROR_MORE_DATA;
        }
        buf[..value.len()].copy_from_slice(value);
        buf[value.len()] = 0;
        *bytes = need as u32;
        0
    }
}

#[test]
fn read_growing_retries_until_the_value_fits() {
    let value: Vec<u16> = (0..500).map(|i| u16::from(b'a') + (i % 26)).collect();
    let got = read_growing(fake_reg(&value)).unwrap();
    assert_eq!(&got[..value.len()], &value[..]);
}

#[test]
fn read_growing_follows_a_value_that_grows_between_calls() {
    let mut calls = 0u32;
    let got = read_growing(|buf, bytes| {
        calls += 1;
        // The value outgrows the buffer offered, twice.
        let need = *bytes + 2 + if calls < 3 { 200 } else { 0 };
        if calls < 3 {
            *bytes = need;
            return ERROR_MORE_DATA;
        }
        buf[0] = u16::from(b'z');
        buf[1] = 0;
        *bytes = 4;
        0
    })
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(&got[..2], &[u16::from(b'z'), 0]);
}

#[test]
fn read_growing_passes_other_errors_through() {
    assert_eq!(read_growing(|_, _| 2), Err(2));
}
