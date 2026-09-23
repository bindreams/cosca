//! The batch gate against a resolver that works from a component list instead of the string.

use super::batch_gate_tests::{the_extension_rule_this_replaced, verbatim_extension_rule_this_replaced};

/// What Win32 does with one path component. The classification is declared, not derived, so the
/// oracle below never re-implements the code it checks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Comp {
    /// An ordinary name. `batch` is whether it reaches a batch file when it ends up final.
    Name { batch: bool },
    /// An empty segment: a repeated separator mid-path, a root at the front — and, TWICE at the
    /// front, the `\\` that opens a UNC root. Kept apart from [`Comp::Skip`] for that last reason.
    Empty,
    /// Contributes nothing: `.`.
    Skip,
    /// Pops the component before it: exactly `..`.
    Pop,
    /// Only dots and spaces, yet neither `.` nor `..` — `...`, `.. `, a lone space. FINAL, Win32
    /// trims it away to nothing and it drops out. Interior it is kept as a name a later `..` pops.
    /// Both measured by the Windows path canary.
    Dots,
    /// A bare drive prefix. Names no file when it ends up final — but only in the path's FIRST
    /// position, the only one a drive prefix can occupy. Anywhere else it is an ordinary name
    /// carrying an unnamed data stream.
    DrivePrefix,
    /// A drive prefix and `..` in one component: `1:..`. In the FIRST position it is that drive's
    /// current directory popped once — somewhere only the per-drive cwd can name, and so nothing
    /// this oracle can see. Anywhere else it trims to `1:`, an ordinary name.
    DriveUp,
    /// `?`: an ordinary name, except right after the leading `\\`, where like `.` it marks a
    /// device root.
    QuestionMark,
}

/// The vocabulary the component generator draws from: one entry per behaviour Win32 has, plus the
/// spellings that have historically been read wrong.
const COMPONENTS: [(&str, Comp); 18] = [
    ("", Comp::Empty),
    (".", Comp::Skip),
    ("..", Comp::Pop),
    // Not `..` with a space: measured, it drops out like every other dots-and-spaces segment.
    (".. ", Comp::Dots),
    ("...", Comp::Dots),
    (" ", Comp::Dots),
    ("y", Comp::Name { batch: false }),
    ("x.exe", Comp::Name { batch: false }),
    ("x.bat", Comp::Name { batch: true }),
    ("x.bat ", Comp::Name { batch: true }),
    ("x.bat.", Comp::Name { batch: true }),
    ("x.bat:s", Comp::Name { batch: true }),
    ("x.bat.:s", Comp::Name { batch: true }),
    ("x.exe:p.bat", Comp::Name { batch: true }),
    (".bat", Comp::Name { batch: true }),
    ("..bat", Comp::Name { batch: true }),
    ("C:", Comp::DrivePrefix),
    ("?", Comp::QuestionMark),
];

/// Drive prefixes that are not an ASCII letter, which Win32 reads as drives all the same:
/// `RtlDetermineDosPathNameType_U` asks only whether `Path[1]` is `:`. `\u{FFFD}` is what a lone
/// surrogate becomes through `to_string_lossy`, and so what the gate sees of one on Windows. `𝒳`
/// is two UTF-16 units, so `𝒳:` is no drive.
const DRIVE_SPELLINGS: [(&str, Comp); 6] = [
    ("1:", Comp::DrivePrefix),
    ("é:", Comp::DrivePrefix),
    ("\u{FFFD}:", Comp::DrivePrefix),
    ("1:..", Comp::DriveUp),
    ("é:..", Comp::DriveUp),
    ("𝒳:", Comp::Name { batch: false }),
];

/// A component read as a ROOT segment of a UNC path, where Win32 takes it by position and never
/// interprets it: the only question left is whether its name is a batch file, and whether it has a
/// name at all once trimmed.
fn as_root_name(comp: Comp) -> Option<bool> {
    match comp {
        Comp::Name { batch } => Some(batch),
        Comp::DrivePrefix | Comp::DriveUp | Comp::QuestionMark => Some(false),
        Comp::Empty | Comp::Skip | Comp::Pop | Comp::Dots => None,
    }
}

/// Where a path made of these components ends up under one reading of its interior [`Comp::Dots`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Landing {
    /// A final name; whether it is a batch file.
    Name(bool),
    /// No final name of its own: popped into the cwd's ancestors, a bare drive, a bare root.
    NoFile,
    /// Collapsed onto a UNC root `\\server\share`.
    UncRoot,
}

/// The root a path opens with, as far as [`oracle_landing`] cares.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Root {
    /// None, a drive, or a single separator: a first-position drive prefix is a drive.
    Plain,
    /// `\\server\share`, which no `..` pops.
    Unc,
    /// `\\.\`, or a slash spelling of `\\?\`: nothing after it is part of the root.
    Device,
}

/// Walk `rest` (the components after any UNC or device root) as a stack, with an interior
/// [`Comp::Dots`] kept as a name a later `..` pops. A FINAL run of them drops out.
fn oracle_landing(rest: &[Comp], root: Root) -> Landing {
    #[derive(Clone, Copy)]
    enum Entry {
        Name(bool),
        Drive,
        Dots,
    }
    let mut stack: Vec<Entry> = Vec::new();
    for (i, comp) in rest.iter().enumerate() {
        match comp {
            Comp::Empty | Comp::Skip => {}
            Comp::Dots => stack.push(Entry::Dots),
            // An empty stack is the root, wherever there is one; popping it is a no-op.
            Comp::Pop => {
                stack.pop();
            }
            // A drive prefix is a prefix only at the very front; elsewhere it is a stream spelling
            // of a file named `C`, which is not a batch name.
            Comp::DrivePrefix if i == 0 && root == Root::Plain => stack.push(Entry::Drive),
            // Popped at once: nothing of it survives, and an empty stack under a plain root is
            // the unseeable cwd.
            Comp::DriveUp if i == 0 && root == Root::Plain => {}
            Comp::DrivePrefix | Comp::DriveUp | Comp::QuestionMark => stack.push(Entry::Name(false)),
            Comp::Name { batch } => stack.push(Entry::Name(*batch)),
        }
    }
    while matches!(stack.last(), Some(Entry::Dots)) {
        stack.pop();
    }
    match stack.last() {
        Some(Entry::Name(batch)) => Landing::Name(*batch),
        Some(Entry::Drive) => Landing::NoFile,
        Some(Entry::Dots) => unreachable!("trailing dots were just dropped"),
        None if root == Root::Unc => Landing::UncRoot,
        None => Landing::NoFile,
    }
}

/// Whether the gate must refuse a path made of these components, resolved the way Win32 resolves
/// one: a stack, `..` pops, and a final name that is a batch file — or no final name at all —
/// refuses.
///
/// Independent of the gate's PARSING, which is the part that has ever been wrong: the components
/// are known here by construction, while `win32_effective_file_name` has to recover them from the
/// joined string, and that re-parse is where every bypass in this gate's history has lived.
///
/// A UNC ROOT is modelled here on its own terms, not borrowed from the gate: two leading
/// [`Comp::Empty`] are the `\\`; the next two components are server and share, by position, and no
/// `..` pops below them — the path resolves to `\\server\share`, whose share is the final name.
/// Modelling the root independently is what makes agreement with the gate meaningful rather than
/// two implementations sharing one mistake.
///
/// A DEVICE root is `\\` followed by `.` or `?` and then a separator or the end: `\\.\` and the
/// slash spellings of `\\?\` (measured: `//?/` and `\\?/` open files like plain paths). Only it is
/// the root — measured, `\\.\C:\x.bat\..` resolves to `\\.\C:` and `\\.\C:\..` to the bare
/// `\\.\` — so the device name is an ordinary component `..` pops, and popped to nothing the
/// path names no file. The literal `\\?\` is std's verbatim prefix, which this oracle does not
/// model; [`compare_gate_with_oracle`] judges those probes by std's literal test instead.
///
/// An interior [`Comp::Dots`] is a name a later `..` pops, as `tests/windows_path_resolution/dots_and_spaces.rs`'s `an_interior_segment_loses_only_a_single_trailing_period` measures.
///
/// Agreement with an oracle hides whatever the two share. This one shares the classification in
/// [`COMPONENTS`] and the "no final name refuses" rule, and nothing else.
fn oracle_refuses(components: &[Comp]) -> bool {
    if let [Comp::Empty, Comp::Empty, Comp::Skip | Comp::QuestionMark, rest @ ..] = components {
        return match oracle_landing(rest, Root::Device) {
            Landing::Name(batch) => batch,
            Landing::NoFile => true,
            Landing::UncRoot => unreachable!("a device path has no UNC root"),
        };
    }
    let (root, rest) = match components {
        [Comp::Empty, Comp::Empty, rest @ ..] => match rest {
            [server, share, rest @ ..] => (Some((*server, *share)), rest),
            // `\\server` alone, or less: no share, nothing loadable.
            _ => return true,
        },
        _ => (None, components),
    };
    let kind = if root.is_some() { Root::Unc } else { Root::Plain };
    match oracle_landing(rest, kind) {
        Landing::Name(batch) => batch,
        Landing::NoFile => true,
        // Collapsed onto `\\server\share`: the share is what std tests.
        Landing::UncRoot => {
            let (_, share) = root.expect("only a UNC path lands on a UNC root");
            as_root_name(share).unwrap_or(true)
        }
    }
}

/// The one over-refusal the gate declares and the oracle does not share: a path collapsed onto its
/// UNC root is refused for a batch-named SERVER as well as a batch-named share, though a `..`
/// inside the root is never collapsed (measured). It may only ever LICENSE a refusal — an
/// acceptance the oracle refuses is a failure whatever this says.
fn declared_unc_over_refusal(components: &[Comp]) -> bool {
    let [Comp::Empty, Comp::Empty, server, _share, rest @ ..] = components else {
        return false;
    };
    as_root_name(*server) == Some(true) && oracle_landing(rest, Root::Unc) == Landing::UncRoot
}

/// The tally of one exhaustive comparison over [`COMPONENTS`].
#[derive(Default, Debug)]
struct Tally {
    probes: u64,
    refused: u64,
    accepted: u64,
    declared_over_refusals: u64,
    /// The gate accepted what the oracle refuses. A hole.
    holes: Vec<String>,
    /// The gate refused what the oracle accepts, outside the declared over-refusal.
    undeclared_over_refusals: Vec<String>,
    /// The gate accepted what the rule it replaced refused.
    newly_accepted: Vec<String>,
    /// The same probe behind `\\?\`: accepted, yet std's literal verbatim test reads it as a batch
    /// file.
    verbatim_holes: Vec<String>,
}

/// Every path of `min_depth..=max_depth` components over `vocab`, under both separators, judged
/// by the gate and by [`oracle_refuses`].
fn compare_gate_with_oracle(vocab: &[(&'static str, Comp)], min_depth: u32, max_depth: u32) -> Tally {
    let mut tally = Tally::default();
    for sep in ["\\", "/"] {
        for depth in min_depth..=max_depth {
            for index in 0..vocab.len().pow(depth) {
                let path = nth_path(vocab, depth, index);
                judge(&mut tally, &path, sep);
            }
        }
    }
    tally
}

/// Like [`compare_gate_with_oracle`] at one depth, with each of `slotted` inserted at `slot`.
fn compare_gate_with_oracle_slotted(
    vocab: &[(&'static str, Comp)],
    depth: u32,
    slot: usize,
    slotted: &[(&'static str, Comp)],
) -> Tally {
    let mut tally = Tally::default();
    for sep in ["\\", "/"] {
        for index in 0..vocab.len().pow(depth) {
            for extra in slotted {
                let mut path = nth_path(vocab, depth, index);
                path.insert(slot, *extra);
                judge(&mut tally, &path, sep);
            }
        }
    }
    tally
}

/// The `index`th path of `depth` components over `vocab`.
fn nth_path(vocab: &[(&'static str, Comp)], depth: u32, mut index: usize) -> Vec<(&'static str, Comp)> {
    (0..depth)
        .map(|_| {
            let component = vocab[index % vocab.len()];
            index /= vocab.len();
            component
        })
        .collect()
}

/// Judge one path, joined with `sep`, by the gate and by [`oracle_refuses`], into `tally`.
fn judge(tally: &mut Tally, path: &[(&str, Comp)], sep: &str) {
    let texts: Vec<&str> = path.iter().map(|(text, _)| *text).collect();
    let kinds: Vec<Comp> = path.iter().map(|(_, kind)| *kind).collect();
    let probe = texts.join(sep);
    let path = std::path::Path::new(&probe);
    let want = oracle_refuses(&kinds);
    let got = super::reject_batch_path_on(path, true).is_err();
    tally.probes += 1;
    if the_extension_rule_this_replaced(path) && !got {
        tally.newly_accepted.push(probe.clone());
    }
    // The verbatim axis: std tests a `\\?\` program as the literal string, so a batch suffix is
    // exactly what it substitutes cmd.exe for.
    let verbatim = format!(r"\\?\{probe}");
    let verbatim_path = std::path::Path::new(&verbatim);
    let verbatim_got = super::reject_batch_path_on(verbatim_path, true).is_err();
    let lower = verbatim.to_ascii_lowercase();
    if (lower.ends_with(".bat") || lower.ends_with(".cmd")) && !verbatim_got {
        tally.verbatim_holes.push(verbatim.clone());
    }
    if verbatim_extension_rule_this_replaced(&verbatim) && !verbatim_got {
        tally.newly_accepted.push(verbatim);
    }
    // `?` after a leading `\\` spells std's verbatim prefix itself: std tests the literal string,
    // and so does this.
    if probe.starts_with(r"\\?\") {
        let lower = probe.to_ascii_lowercase();
        if (lower.ends_with(".bat") || lower.ends_with(".cmd")) && !got {
            tally.verbatim_holes.push(probe);
        }
        return;
    }
    match (want, got) {
        (true, false) => tally.holes.push(probe),
        (false, true) if declared_unc_over_refusal(&kinds) => {
            tally.declared_over_refusals += 1;
        }
        (false, true) => tally.undeclared_over_refusals.push(probe),
        (_, true) => tally.refused += 1,
        (_, false) => tally.accepted += 1,
    }
}

/// Assert `tally` found no disagreement, and that it saw both verdicts.
fn assert_agreement(mut tally: Tally) -> Tally {
    // Truncated: a broken gate disagrees on tens of thousands of probes and the list is unreadable.
    tally.holes.truncate(20);
    tally.undeclared_over_refusals.truncate(20);
    tally.newly_accepted.truncate(20);
    tally.verbatim_holes.truncate(20);
    assert_eq!(
        tally.verbatim_holes,
        Vec::<String>::new(),
        "a verbatim batch suffix accepted"
    );
    assert_eq!(
        tally.holes,
        Vec::<String>::new(),
        "the gate accepts what Win32 resolves to a batch file"
    );
    assert_eq!(
        tally.undeclared_over_refusals,
        Vec::<String>::new(),
        "the gate refuses what Win32 does not resolve to a batch file"
    );
    assert_eq!(
        tally.newly_accepted,
        Vec::<String>::new(),
        "refused before, accepted now"
    );
    // A generator that emitted only refusals (or only acceptances) would agree with a gate that
    // had lost the other answer entirely, and would say nothing while doing it.
    assert!(tally.refused > 1000 && tally.accepted > 1000, "{tally:?}");
    tally
}

/// Exhaustive over COMPONENTS: every path up to five components deep over [`COMPONENTS`], under
/// both separators, checked against a resolver that works from the component list instead of the
/// string.
///
/// This is the envelope the character-level test cannot reach. Its shortest interesting probe,
/// `.bat\a\..`, is nine characters; enumerating that many characters over a twelve-character
/// alphabet is 12^9 — over five billion probes — and the spellings that have actually bypassed
/// this gate all live out there. Five components is the least that reaches a UNC pop:
/// `\\srv\x.bat\..` is `["", "", "srv", "x.bat", ".."]`.
///
/// Every probe is judged a second time behind `\\?\`, where no oracle is needed: std's verbatim
/// test is a literal suffix check, so a `.bat`/`.cmd` suffix must be refused and nothing else is
/// asserted.
///
/// Exact agreement but for one declared over-refusal: the gate is allowed to refuse a directory
/// and is not allowed to refuse `y\x.bat\..`, which loads `y`. Carries the no-regression property
/// at this length as well — nothing the rule it replaced refused may come out accepted.
#[test]
fn the_gate_agrees_with_a_component_level_resolver() {
    let tally = assert_agreement(compare_gate_with_oracle(&COMPONENTS, 1, 5));
    // One that never reached the declared over-refusal would never have exercised a UNC root
    // collapse.
    assert!(tally.declared_over_refusals > 0, "{tally:?}");
}

/// The same comparison over [`COMPONENTS`] plus [`DRIVE_SPELLINGS`]: every path up to four
/// components, and at five a drive spelling in the share or device slot (`\\.\1:\..` is
/// `["", "", ".", "1:", ".."]`). Adding them to the depth-five run above would triple its cost.
#[test]
fn the_gate_agrees_on_every_drive_spelling() {
    let vocab: Vec<(&str, Comp)> = COMPONENTS.iter().chain(&DRIVE_SPELLINGS).copied().collect();
    assert_agreement(compare_gate_with_oracle(&vocab, 1, 4));
    assert_agreement(compare_gate_with_oracle_slotted(&COMPONENTS, 4, 3, &DRIVE_SPELLINGS));
}

/// The oracle's UNC model, pinned on the rows the gate once got wrong: an oracle without it
/// accepts them, and then agreeing with it proves nothing about them.
#[test]
fn the_oracle_models_a_unc_root_of_its_own() {
    let name = |batch| Comp::Name { batch };
    let e = Comp::Empty;
    // `\\y\x.bat\..`
    assert!(oracle_refuses(&[e, e, name(false), name(true), Comp::Pop]));
    // `\\y\x.bat\y\..\..`
    assert!(oracle_refuses(&[
        e,
        e,
        name(false),
        name(true),
        name(false),
        Comp::Pop,
        Comp::Pop
    ]));
    // `\\...\x.bat\y\..` — a dots-only server is a server, not a component to skip.
    assert!(oracle_refuses(&[e, e, Comp::Dots, name(true), name(false), Comp::Pop]));
    // `\\y\y\x.bat\..` pops back to the share `y`, which is no batch file.
    assert!(!oracle_refuses(&[
        e,
        e,
        name(false),
        name(false),
        name(true),
        Comp::Pop
    ]));
    // `\y\x.bat\..` has ONE leading separator: a rooted path, not a UNC one.
    assert!(!oracle_refuses(&[e, name(false), name(true), Comp::Pop]));
}

/// The oracle's device root, pinned on the rows where a UNC-shaped root disagrees with the
/// measured one: `..` pops the device name, and the bare `\\.\` names no file.
#[test]
fn the_oracle_models_a_device_root_of_its_own() {
    let name = |batch| Comp::Name { batch };
    let (e, dot, q) = (Comp::Empty, Comp::Skip, Comp::QuestionMark);
    // `\\.\x.bat\..` and `\\.\y\..` resolve to `\\.\`.
    assert!(oracle_refuses(&[e, e, dot, name(true), Comp::Pop]));
    assert!(oracle_refuses(&[e, e, dot, name(false), Comp::Pop]));
    // `\\.\C:\..`: the device name `C:` pops like any other.
    assert!(oracle_refuses(&[e, e, dot, Comp::DrivePrefix, Comp::Pop]));
    // `\\.\C:` names `C:`, a device, not a bare drive.
    assert!(!oracle_refuses(&[e, e, dot, Comp::DrivePrefix]));
    // `//?/C:/...` is a device path too, and the final `...` drops out.
    assert!(!oracle_refuses(&[e, e, q, Comp::DrivePrefix, Comp::Dots]));
    // `\\.\C:\..\..\x.bat`
    assert!(oracle_refuses(&[
        e,
        e,
        dot,
        Comp::DrivePrefix,
        Comp::Pop,
        Comp::Pop,
        name(true)
    ]));
    // `\\.\y\x.bat\..`
    assert!(!oracle_refuses(&[e, e, dot, name(false), name(true), Comp::Pop]));
}

/// The oracle's reading of `.. ` and of an interior dots-and-spaces segment, pinned for the same
/// reason as its UNC root: the gate got both wrong once, and an oracle that shared the mistake
/// would have agreed with it.
#[test]
fn the_oracle_reads_dots_and_spaces_on_its_own_terms() {
    let name = |batch| Comp::Name { batch };
    // `x.bat\y\.. ` — final, so it drops out and `y` is the name.
    assert!(!oracle_refuses(&[name(true), name(false), Comp::Dots]));
    // `y\x.bat\...\..` — kept as a name, the `..` pops it and exposes `x.bat`.
    assert!(oracle_refuses(&[name(false), name(true), Comp::Dots, Comp::Pop]));
    // `x.bat\y\...\..` — kept as a name, the `..` pops it and `y` stays.
    assert!(!oracle_refuses(&[name(true), name(false), Comp::Dots, Comp::Pop]));
    // `a\...\..\b` — lands on `b`.
    assert!(!oracle_refuses(&[name(false), Comp::Dots, Comp::Pop, name(false)]));
}
