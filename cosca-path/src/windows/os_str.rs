//! Windows strings: UTF-16, possibly ill-formed, stored as WTF-8.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::ops::Deref;

use ref_cast::{ref_cast_custom, RefCastCustom};

/// A borrowed Windows string: UTF-16, possibly ill-formed. `Debug` is faithful: a lone surrogate
/// shows as `\u{D800}`.
#[derive(RefCastCustom, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct OsStr([u8]);

/// An owned [`OsStr`].
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OsString(pub(super) Vec<u8>);

impl OsStr {
    /// Borrows `s` as an `OsStr`, without copying.
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &OsStr {
        s.as_ref()
    }

    /// Borrows well-formed WTF-8 as an `OsStr`.
    #[ref_cast_custom]
    pub(super) const fn from_wtf8(bytes: &[u8]) -> &OsStr;

    pub(super) fn as_wtf8(&self) -> &[u8] {
        &self.0
    }

    /// The string as UTF-16 units.
    pub fn to_wide(&self) -> Vec<u16> {
        let mut units = Vec::with_capacity(self.0.len());
        for chunk in wtf8_chunks(&self.0) {
            match chunk {
                Chunk::Str(s) => units.extend(s.encode_utf16()),
                Chunk::Surrogate(unit) => units.push(unit),
            }
        }
        units
    }

    /// The string as `str`, if it holds no lone surrogate.
    pub fn to_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// The string with each lone surrogate replaced by U+FFFD.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        if let Some(s) = self.to_str() {
            return Cow::Borrowed(s);
        }
        let mut out = String::with_capacity(self.0.len());
        for chunk in wtf8_chunks(&self.0) {
            match chunk {
                Chunk::Str(s) => out.push_str(s),
                Chunk::Surrogate(_) => out.push(char::REPLACEMENT_CHARACTER),
            }
        }
        Cow::Owned(out)
    }

    /// The string as a `std` OS string, unit for unit. A path's [stored text](super::Path::as_os_str)
    /// stays a lexical spelling, not a string for Win32. [`ToOwned::to_owned`] clones into an
    /// [`OsString`].
    #[cfg(windows)]
    pub fn to_os_string(&self) -> std::ffi::OsString {
        use std::os::windows::ffi::OsStringExt;
        std::ffi::OsString::from_wide(&self.to_wide())
    }
}

/// A run of WTF-8: valid UTF-8, or one lone surrogate.
enum Chunk<'a> {
    Str(&'a str),
    Surrogate(u16),
}

/// The UTF-8 runs and lone surrogates of well-formed WTF-8, in order.
fn wtf8_chunks(mut bytes: &[u8]) -> impl Iterator<Item = Chunk<'_>> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        // A surrogate is `ED A0..=BF xx`; nothing valid starts with that.
        let is_surrogate = |b: &[u8]| b.len() >= 3 && b[0] == 0xED && b[1] >= 0xA0;
        if is_surrogate(bytes) {
            let unit = 0xD000 | (u16::from(bytes[1] & 0x3F) << 6) | u16::from(bytes[2] & 0x3F);
            bytes = &bytes[3..];
            return Some(Chunk::Surrogate(unit));
        }
        let end = (1..bytes.len())
            .find(|&i| is_surrogate(&bytes[i..]))
            .unwrap_or(bytes.len());
        let (run, rest) = bytes.split_at(end);
        bytes = rest;
        match std::str::from_utf8(run) {
            Ok(s) => Some(Chunk::Str(s)),
            Err(_) => unreachable!("WTF-8 between lone surrogates is UTF-8"),
        }
    })
}

impl fmt::Debug for OsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for chunk in wtf8_chunks(&self.0) {
            match chunk {
                Chunk::Str(s) => write!(f, "{}", s.escape_debug())?,
                Chunk::Surrogate(unit) => write!(f, "\\u{{{unit:X}}}")?,
            }
        }
        f.write_str("\"")
    }
}

impl ToOwned for OsStr {
    type Owned = OsString;
    fn to_owned(&self) -> OsString {
        OsString(self.0.to_vec())
    }
}

impl AsRef<OsStr> for OsStr {
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl AsRef<OsStr> for str {
    fn as_ref(&self) -> &OsStr {
        OsStr::from_wtf8(self.as_bytes())
    }
}

impl AsRef<OsStr> for String {
    fn as_ref(&self) -> &OsStr {
        self.as_str().as_ref()
    }
}

impl AsRef<OsStr> for OsString {
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl OsString {
    pub fn new() -> OsString {
        OsString(Vec::new())
    }

    /// The string `units` spell, lone surrogates kept.
    pub fn from_wide(units: &[u16]) -> OsString {
        let mut bytes = Vec::with_capacity(units.len());
        for unit in char::decode_utf16(units.iter().copied()) {
            match unit {
                Ok(c) => bytes.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
                Err(e) => {
                    let u = e.unpaired_surrogate();
                    // The three-byte form UTF-8 would use, were surrogates characters.
                    bytes.extend_from_slice(&[
                        0xE0 | (u >> 12) as u8,
                        0x80 | ((u >> 6) & 0x3F) as u8,
                        0x80 | (u & 0x3F) as u8,
                    ]);
                }
            }
        }
        OsString(bytes)
    }

    pub fn as_os_str(&self) -> &OsStr {
        OsStr::from_wtf8(&self.0)
    }
}

impl Deref for OsString {
    type Target = OsStr;
    fn deref(&self) -> &OsStr {
        self.as_os_str()
    }
}

impl Borrow<OsStr> for OsString {
    fn borrow(&self) -> &OsStr {
        self
    }
}

impl fmt::Debug for OsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_os_str(), f)
    }
}

impl From<&str> for OsString {
    fn from(s: &str) -> OsString {
        OsString(s.as_bytes().to_vec())
    }
}

impl From<String> for OsString {
    fn from(s: String) -> OsString {
        OsString(s.into_bytes())
    }
}

#[cfg(windows)]
impl From<&std::ffi::OsStr> for OsString {
    fn from(s: &std::ffi::OsStr) -> OsString {
        use std::os::windows::ffi::OsStrExt;
        OsString::from_wide(&s.encode_wide().collect::<Vec<_>>())
    }
}
