//! The shim's wire protocol: the invocation argv, the frames the shim sends cosca, and the commands
//! cosca sends the shim. Pure: no I/O, no system calls.
//!
//! Every value has exactly one encoding, so a decoder never accepts two spellings of one thing.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// `argv[1]` of a plain invocation.
const FLAG: &[u8] = b"--cosca-elevation-shim=1";
/// `argv[1]` of a hex invocation: every argument after it except [`SEPARATOR`] is lowercase hex, so
/// the text survives `osascript`, which is not byte-transparent.
const FLAG_HEX: &[u8] = b"--cosca-elevation-shim=1x";
const FLAG_PREFIX: &[u8] = b"--cosca-elevation-shim";
const SEPARATOR: &str = "--";
/// Index of [`SEPARATOR`]: `[exe, flag, dir, pid, identity, euid, search, "--", program, args…]`.
const SEPARATOR_AT: usize = 7;
/// The identity field is `uniq:ver` on macOS and `-` on Linux; the other form is an error there.
pub(crate) const IDENTITY_PRESENT: bool = cfg!(target_os = "macos");

/// Raw `i32` newtypes: rustix's `Errno` and `Signal` are unavailable on macOS with this crate's features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Errno(pub(crate) i32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Signal(pub(crate) i32);

/// macOS: cosca's `p_uniqueid` and `p_idversion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ShimIdentity {
    pub(crate) unique_id: u64,
    pub(crate) id_version: u32,
}

/// What the shim is told on its command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShimArgs {
    /// The private directory holding cosca's listener. Absolute.
    pub(crate) dir: PathBuf,
    pub(crate) cosca_pid: u32,
    pub(crate) cosca_identity: Option<ShimIdentity>,
    pub(crate) cosca_euid: u32,
    /// `None`: search the shim's own `PATH`. `Some`: search this one; empty is a real, empty `PATH`.
    pub(crate) search_path: Option<OsString>,
    pub(crate) program: OsString,
    pub(crate) args: Vec<OsString>,
}

/// Why argv is not a valid shim invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ShimArgsError {
    #[error("unknown protocol version")]
    UnknownVersion,
    #[error("too few arguments")]
    TooFewArguments,
    #[error("the separator `--` is missing")]
    MissingSeparator,
    #[error("malformed hex argument (lowercase hex only)")]
    BadHex,
    /// execve cannot carry a NUL, so neither form may.
    #[error("an argument contains a NUL")]
    EmbeddedNul,
    #[error("malformed number")]
    BadNumber,
    #[error("malformed identity")]
    BadIdentity,
    #[error("the directory is empty or not absolute")]
    BadDir,
    #[error("malformed search path")]
    BadSearch,
}

impl ShimArgs {
    /// The full argv, `argv[0]` included, laid out as at [`SEPARATOR_AT`]; `hex` selects the hex form
    /// ([`FLAG_HEX`]). `dir` must be absolute.
    pub(crate) fn to_argv(&self, exe: &OsStr, hex: bool) -> Vec<OsString> {
        self.to_argv_for(exe, hex, IDENTITY_PRESENT)
    }

    /// [`to_argv`](Self::to_argv) for a platform that does (`identity_present`) or does not carry an
    /// identity.
    fn to_argv_for(&self, exe: &OsStr, hex: bool, identity_present: bool) -> Vec<OsString> {
        let identity = match self.cosca_identity {
            None => OsString::from("-"),
            Some(ShimIdentity { unique_id, id_version }) => OsString::from(format!("{unique_id}:{id_version}")),
        };
        let search = match &self.search_path {
            None => OsString::from("-"),
            Some(path) => {
                let mut token = OsString::from("P");
                token.push(path);
                token
            }
        };
        let before: [OsString; 5] = [
            self.dir.clone().into_os_string(),
            self.cosca_pid.to_string().into(),
            identity,
            self.cosca_euid.to_string().into(),
            search,
        ];
        debug_assert!(
            before
                .iter()
                .chain([&self.program])
                .chain(&self.args)
                .all(|a| !a.as_bytes().contains(&0)),
            "execve cannot carry a NUL"
        );
        debug_assert!(self.dir.is_absolute(), "the dir must be absolute");
        debug_assert_eq!(
            self.cosca_identity.is_some(),
            identity_present,
            "identity is present exactly when identity_present"
        );
        let encode = |a: OsString| if hex { to_hex(&a) } else { a };

        let mut argv = Vec::with_capacity(SEPARATOR_AT + 2 + self.args.len());
        argv.push(exe.to_owned());
        argv.push(OsStr::from_bytes(if hex { FLAG_HEX } else { FLAG }).to_owned());
        argv.extend(before.into_iter().map(encode));
        argv.push(SEPARATOR.into());
        argv.push(encode(self.program.clone()));
        argv.extend(self.args.iter().cloned().map(encode));
        argv
    }

    /// `Ok(None)` when `argv` is not a shim invocation at all; an error when it claims to be one and
    /// is not valid. `argv` includes `argv[0]`.
    pub(crate) fn parse(argv: &[OsString]) -> Result<Option<ShimArgs>, ShimArgsError> {
        Self::parse_for(argv, IDENTITY_PRESENT)
    }

    /// [`parse`](Self::parse) for a platform that does (`identity_present`) or does not carry an
    /// identity.
    fn parse_for(argv: &[OsString], identity_present: bool) -> Result<Option<ShimArgs>, ShimArgsError> {
        let Some(flag) = argv.get(1) else { return Ok(None) };
        if !flag.as_bytes().starts_with(FLAG_PREFIX) {
            return Ok(None);
        }
        let hex = match flag.as_bytes() {
            FLAG => false,
            FLAG_HEX => true,
            _ => return Err(ShimArgsError::UnknownVersion),
        };
        if argv.len() <= SEPARATOR_AT + 1 {
            return Err(ShimArgsError::TooFewArguments);
        }
        if argv[SEPARATOR_AT] != SEPARATOR {
            return Err(ShimArgsError::MissingSeparator);
        }

        let decoded: Vec<OsString>;
        let fields: &[OsString] = if hex {
            decoded = argv[2..]
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    if i + 2 == SEPARATOR_AT {
                        Ok(a.clone())
                    } else {
                        from_hex(a)
                    }
                })
                .collect::<Result<_, _>>()?;
            &decoded
        } else {
            &argv[2..]
        };
        if fields.iter().any(|a| a.as_bytes().contains(&0)) {
            return Err(ShimArgsError::EmbeddedNul);
        }
        // `fields[i]` is `argv[i + 2]`.
        let [dir, pid, identity, euid, search, _separator, program, args @ ..] = fields else {
            unreachable!("length checked above")
        };
        if !Path::new(dir).is_absolute() {
            return Err(ShimArgsError::BadDir);
        }
        Ok(Some(ShimArgs {
            dir: PathBuf::from(dir),
            cosca_pid: decimal_u32(pid)?,
            cosca_identity: parse_identity(identity, identity_present)?,
            cosca_euid: decimal_u32(euid)?,
            search_path: parse_search(search)?,
            program: program.clone(),
            args: args.to_vec(),
        }))
    }
}

fn to_hex(a: &OsStr) -> OsString {
    use std::fmt::Write;
    let mut s = String::with_capacity(a.len() * 2);
    for b in a.as_bytes() {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s.into()
}

fn from_hex(a: &OsStr) -> Result<OsString, ShimArgsError> {
    let (pairs, odd) = a.as_bytes().as_chunks::<2>();
    if !odd.is_empty() {
        return Err(ShimArgsError::BadHex);
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(ShimArgsError::BadHex),
    };
    let out = pairs
        .iter()
        .map(|[hi, lo]| Ok(nibble(*hi)? << 4 | nibble(*lo)?))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(OsString::from_vec(out))
}

/// Decimal digits only: no sign, no whitespace, no leading zero, so a number has one encoding.
fn decimal<T: std::str::FromStr>(a: &[u8]) -> Option<T> {
    if a.is_empty() || !a.iter().all(u8::is_ascii_digit) || (a.len() > 1 && a[0] == b'0') {
        return None;
    }
    std::str::from_utf8(a).ok()?.parse().ok()
}

fn decimal_u32(a: &OsStr) -> Result<u32, ShimArgsError> {
    decimal(a.as_bytes()).ok_or(ShimArgsError::BadNumber)
}

fn parse_identity(a: &OsStr, identity_present: bool) -> Result<Option<ShimIdentity>, ShimArgsError> {
    if !identity_present {
        return if a.as_bytes() == b"-" {
            Ok(None)
        } else {
            Err(ShimArgsError::BadIdentity)
        };
    }
    let mut halves = a.as_bytes().split(|&b| b == b':');
    let (Some(unique_id), Some(id_version), None) = (halves.next(), halves.next(), halves.next()) else {
        return Err(ShimArgsError::BadIdentity);
    };
    Ok(Some(ShimIdentity {
        unique_id: decimal(unique_id).ok_or(ShimArgsError::BadIdentity)?,
        id_version: decimal(id_version).ok_or(ShimArgsError::BadIdentity)?,
    }))
}

fn parse_search(a: &OsStr) -> Result<Option<OsString>, ShimArgsError> {
    match a.as_bytes() {
        b"-" => Ok(None),
        [b'P', path @ ..] => Ok(Some(OsString::from_vec(path.to_vec()))),
        _ => Err(ShimArgsError::BadSearch),
    }
}

/// Why the program never ran; the shim has positive evidence of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotExecuted {
    ForkFailed(Errno),
    ExecFailed(Errno),
    SetupFailed(Errno),
    TerminatedBeforeExec(Signal),
}

/// Why the shim refused after hello. The value is also the shim's exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The answer was not written by cosca.
    NotCosca = 122,
    /// Cosca exited before the start.
    CoscaGone = 123,
    /// No answer arrived.
    NoAnswer = 124,
    /// Cosca answered `N`.
    Denied = 125,
}

impl Refusal {
    fn from_code(code: u8) -> Option<Refusal> {
        [
            Refusal::NotCosca,
            Refusal::CoscaGone,
            Refusal::NoAnswer,
            Refusal::Denied,
        ]
        .into_iter()
        .find(|r| *r as u8 == code)
    }
}

/// One shim-to-cosca frame. `Hello` is the single byte `H`; the rest are a tag and a little-endian
/// `i32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Frame {
    Hello,
    /// `S`: the program's wait status.
    Status(i32),
    /// `L`: the possibly-started program was killed after supervision failed; its wait status.
    Lost(i32),
    /// `U`: the program has exited and its status is lost. The payload is zero.
    StatusLost,
    /// `F`: positive evidence the program never ran. The payload is `kind << 16 | value`, with
    /// `value` nonzero.
    NotExecuted(NotExecuted),
    /// `R`: refused after hello.
    Refused(Refusal),
}

/// A frame that cannot be decoded. Callers treat both the same.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum FrameError {
    /// A valid prefix: more bytes may follow.
    #[error("truncated frame")]
    Truncated,
    /// Never a valid frame, whatever follows.
    #[error("garbled frame")]
    Garbled,
}

const KIND_FORK: u16 = 1;
const KIND_EXEC: u16 = 2;
const KIND_SETUP: u16 = 3;
const KIND_TERM: u16 = 4;

impl Frame {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let (tag, value) = match *self {
            Frame::Hello => return vec![b'H'],
            Frame::Status(ws) => (b'S', ws),
            Frame::Lost(ws) => (b'L', ws),
            Frame::StatusLost => (b'U', 0),
            Frame::NotExecuted(n) => {
                let (kind, value) = match n {
                    NotExecuted::ForkFailed(Errno(e)) => (KIND_FORK, e),
                    NotExecuted::ExecFailed(Errno(e)) => (KIND_EXEC, e),
                    NotExecuted::SetupFailed(Errno(e)) => (KIND_SETUP, e),
                    NotExecuted::TerminatedBeforeExec(Signal(s)) => (KIND_TERM, s),
                };
                debug_assert!(
                    (1..=0xffff).contains(&value),
                    "an F value is nonzero and fits 16 bits: {value}"
                );
                (b'F', i32::from(kind) << 16 | value & 0xffff)
            }
            Frame::Refused(r) => (b'R', r as i32),
        };
        let mut out = vec![tag];
        out.extend_from_slice(&value.to_le_bytes());
        out
    }
}

/// Whether payload byte `i` of a frame tagged `tag` can belong to a valid frame, given the payload
/// bytes before it (`p[..=i]` are present).
fn payload_byte_ok(tag: u8, p: &[u8], i: usize) -> bool {
    match (tag, i) {
        (b'U', _) | (b'R', 1..) => p[i] == 0,
        (b'R', 0) => Refusal::from_code(p[0]).is_some(),
        // The 16-bit value, nonzero, then the 16-bit kind, 1 to 4.
        (b'F', 1) => p[0] != 0 || p[1] != 0,
        (b'F', 2) => (1..=4).contains(&p[2]),
        (b'F', 3) => p[3] == 0,
        _ => true,
    }
}

/// Decodes exactly one frame: `bytes` is the whole frame, no more and no less. A prefix that no
/// continuation could complete is `Garbled`, not `Truncated`.
pub(crate) fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameError> {
    let Some((&tag, payload)) = bytes.split_first() else {
        return Err(FrameError::Truncated);
    };
    if !b"HSLUFR".contains(&tag) {
        return Err(FrameError::Garbled);
    }
    if tag == b'H' {
        return if payload.is_empty() {
            Ok(Frame::Hello)
        } else {
            Err(FrameError::Garbled)
        };
    }
    if !(0..payload.len().min(4)).all(|i| payload_byte_ok(tag, payload, i)) || payload.len() > 4 {
        return Err(FrameError::Garbled);
    }
    let Ok(payload) = <[u8; 4]>::try_from(payload) else {
        return Err(FrameError::Truncated);
    };
    let value = i32::from_le_bytes(payload);
    let (kind, low) = ((value >> 16) as u16, value & 0xffff);
    Ok(match tag {
        b'S' => Frame::Status(value),
        b'L' => Frame::Lost(value),
        b'U' => Frame::StatusLost,
        b'R' => Frame::Refused(Refusal::from_code(payload[0]).expect("checked per byte")),
        b'F' => Frame::NotExecuted(match kind {
            KIND_FORK => NotExecuted::ForkFailed(Errno(low)),
            KIND_EXEC => NotExecuted::ExecFailed(Errno(low)),
            KIND_SETUP => NotExecuted::SetupFailed(Errno(low)),
            KIND_TERM => NotExecuted::TerminatedBeforeExec(Signal(low)),
            _ => unreachable!("checked per byte"),
        }),
        _ => unreachable!("tag checked above"),
    })
}

/// One cosca-to-shim byte. The first one sent is `Allow` or `Deny`, once, and only after `Hello`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    /// `A`: start the program.
    Allow,
    /// `N`: do not start it.
    Deny,
    /// `K`: SIGKILL the program.
    Kill,
    /// `T`: SIGTERM the program.
    Terminate,
    /// `D`: stop supervising; the program outlives cosca.
    Disarm,
    /// `P`: an ordering ping. Valid only where test hooks are installed; the receiver decides, so
    /// this layer decodes it everywhere.
    Ping,
}

/// A byte that is no [`Command`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown command byte {0:#04x}")]
pub(crate) struct UnknownCommand(pub(crate) u8);

impl Command {
    pub(crate) fn encode(self) -> u8 {
        match self {
            Command::Allow => b'A',
            Command::Deny => b'N',
            Command::Kill => b'K',
            Command::Terminate => b'T',
            Command::Disarm => b'D',
            Command::Ping => b'P',
        }
    }

    pub(crate) fn decode(byte: u8) -> Result<Command, UnknownCommand> {
        Ok(match byte {
            b'A' => Command::Allow,
            b'N' => Command::Deny,
            b'K' => Command::Kill,
            b'T' => Command::Terminate,
            b'D' => Command::Disarm,
            b'P' => Command::Ping,
            _ => return Err(UnknownCommand(byte)),
        })
    }
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod protocol_tests;
