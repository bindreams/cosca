//! std-only spawn: resolve our Stdio model onto `std::process::Command`, wire
//! the program/args via the Plan-1 quoters, and spawn through `shared_child`.

use std::collections::BTreeMap;
use std::process::Stdio as StdStdio;

use shared_child::SharedChild;

use crate::child::{Child, ParentEnd};
use crate::command::{Command, CommandInput, EnvOp};
use crate::error::Error;
use crate::identity::ProcessId;
use crate::stdio::{Direction, Fd, ResolvedStdio};

// A child-side descriptor handed to std via `Stdio::from`.
#[cfg(unix)]
type ChildEnd = std::os::unix::io::OwnedFd;
#[cfg(windows)]
type ChildEnd = std::os::windows::io::OwnedHandle;

pub(crate) fn spawn(cmd: &mut Command) -> Result<Child, Error> {
    let fds = std::mem::take(cmd.fds_mut());
    let kill_on_drop = cmd.kill_on_drop_flag();

    // On Windows, fd >= 3 is unsupported in this plan (no MSVCRT fd-table wiring).
    // On Unix, arbitrary fds are handled below via command-fds.
    #[cfg(windows)]
    for slot in fds.keys() {
        if slot.raw() >= 3 {
            return Err(Error::Unsupported {
                op: format!("{slot}"),
                platform: std::env::consts::OS,
                detail: "arbitrary descriptors (>= 3) require the raw backend (Plan 4)".into(),
            });
        }
    }
    // Reject merge-targeting-a-merge: the two-pass algorithm only resolves one
    // level of indirection. Transitive chaining requires a fixpoint loop and is
    // deferred to the raw backend.
    for slot in fds.keys() {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(slot) {
            if matches!(fds.get(target), Some(ResolvedStdio::Merge(_))) {
                return Err(Error::Unsupported {
                    op: format!("merge {slot} -> {target} -> <another merge>"),
                    platform: std::env::consts::OS,
                    detail: "chained merges (merge-to-merge) are not supported; \
                             redirect to a concrete slot (pipe/file/null/inherit)"
                        .into(),
                });
            }
        }
    }

    let mut std_cmd = build_std_command(cmd)?;

    // Resolve every configured slot to a (child-side ChildEnd, optional parent
    // end). On Unix this covers both 0/1/2 and n>=3; on Windows only 0/1/2 reach
    // here (n>=3 are rejected above). Two-pass: non-merge first so merge can dup.
    let mut child_ends: BTreeMap<Fd, ChildEnd> = BTreeMap::new();
    let mut parent_ends: BTreeMap<Fd, ParentEnd> = BTreeMap::new();

    // First pass: resolve all non-merge slots. On Unix iterate all configured fds;
    // on Windows the rejection above ensures only 0/1/2 exist. The std slots 0/1/2
    // default to inherit when not explicitly configured; n>=3 have no default.
    let std_slots = [Fd::STDIN, Fd::STDOUT, Fd::STDERR];
    let all_slots: Vec<Fd> = {
        // Yield 0/1/2 first (even unconfigured, for inherit defaulting), then any
        // configured n>=3. The n>=3 collection is Unix-only: on Windows the
        // early rejection above guarantees `fds` holds no fd>=3, so the push is
        // dead code there — cfg-gate it to make that explicit (and avoid an
        // unused-`mut` warning on Windows where nothing is pushed).
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut v: Vec<Fd> = std_slots.to_vec();
        #[cfg(unix)]
        for &fd in fds.keys() {
            if fd.raw() >= 3 {
                v.push(fd);
            }
        }
        v
    };
    for slot in all_slots {
        let resolved = fds.get(&slot);
        if let Some(ResolvedStdio::Merge(_)) = resolved {
            continue; // second pass
        }
        // n>=3 slots have no inherit default; skip unconfigured ones.
        if slot.raw() >= 3 && resolved.is_none() {
            continue;
        }
        let (child_end, parent) = resolve_non_merge(slot, resolved)?;
        if let Some(p) = parent {
            parent_ends.insert(slot, p);
        }
        child_ends.insert(slot, child_end);
    }
    // Second pass: merges dup an already-resolved target's child end (any slot).
    for slot in fds.keys() {
        if let Some(ResolvedStdio::Merge(target)) = fds.get(slot) {
            let src = child_ends.get(target).ok_or_else(|| Error::Unsupported {
                op: format!("merge {slot} -> {target}"),
                platform: std::env::consts::OS,
                detail: "merge target descriptor is not configured".into(),
            })?;
            child_ends.insert(*slot, dup(src)?);
        }
    }

    // Hand 0/1/2 child ends to std (consumes them; std closes its copies on spawn).
    for slot in std_slots {
        if let Some(end) = child_ends.remove(&slot) {
            let stdio = StdStdio::from(end);
            match slot {
                Fd::STDIN => std_cmd.stdin(stdio),
                Fd::STDOUT => std_cmd.stdout(stdio),
                _ => std_cmd.stderr(stdio),
            };
        }
    }

    // Phase 1 (before spawn): root detection + pre-spawn containment setup. This
    // MUST run before the command-fds block below so that command-fds installs
    // the LAST pre_exec hook. Why ordering matters: pre_exec hooks run in
    // registration order in the forked child. The Linux cgroup self-placement
    // hook (registered inside `prepare`) writes "0" to a pre-opened cgroup.procs
    // fd whose CLOEXEC is cleared (so it is inherited across fork). If
    // command-fds' dup2 ran FIRST, it could dup2 the user's fd over the number
    // that cgroup.procs fd occupies — closing/replacing it — so the later cgroup
    // write would hit a closed/wrong fd (silent CgroupV2->ProcessGroup downgrade,
    // or a stray "0" corrupting the user's fd). By running command-fds LAST, the
    // cgroup write+close happens while its fd is still valid; command-fds may then
    // freely reuse the now-closed slot. Net child order: std stdio (0/1/2) ->
    // containment pre_execs (cgroup placement / setsid) -> command-fds dup2 (last).
    let prepared = crate::containment::prepare(&mut std_cmd, &cmd.contain_request());

    // On Unix, hand n>=3 child ends to command-fds. This installs a pre_exec hook
    // that dup2's each OwnedFd to its target number post-fork. It is registered
    // LAST (after `prepare` above) so its dup2 cannot clobber the cgroup
    // self-placement fd; std also dup2's 0/1/2 before any pre_exec runs (std
    // disables posix_spawn when hooks are registered), so our n>=3 mappings never
    // clobber the std stdio fds either. FdMappingCollision is unreachable:
    // child_ends keys come from a BTreeMap, so each child fd number is unique.
    #[cfg(unix)]
    {
        use command_fds::{CommandFdExt, FdMapping};

        let mappings: Vec<FdMapping> = child_ends
            .into_iter()
            .map(|(fd, owned)| FdMapping {
                parent_fd: owned,
                child_fd: fd.raw(),
            })
            .collect();
        if !mappings.is_empty() {
            std_cmd
                .fd_mappings(mappings)
                .expect("child fd numbers are unique (BTreeMap keys)");
        }
    }

    // We own the std Child so containment can job-assign + resume it (Task 5).
    let child = std_cmd.spawn().map_err(Error::Io)?;
    // Phase 2 (after spawn, before adopt): attach the mechanism (job/cgroup/...).
    // `prepared` is consumed here: Linux cgroup leaf ownership moves to Attached::Cgroup.
    let (containment, attached) = crate::containment::attach(&child, prepared)?;
    // Read identity BEFORE adopting into SharedChild. `SharedChild::new` calls
    // `try_wait()`, which REAPS an already-exited child — and a short-lived child
    // (e.g. `exit 0`, `sid-report`) can exit before we reach this point. Once
    // reaped, /proc/<pid> is gone and the identity is unresolvable (observed as a
    // load-dependent "vanished" race under parallel spawns). While we still own
    // the un-reaped `std::process::Child`, the child is at worst a zombie — on
    // Unix its /proc entry persists; on Windows the std Child pins the process
    // handle so the pid cannot be reused — so this read is race-free.
    let id = ProcessId::of(child.id()).ok_or_else(|| {
        Error::Io(std::io::Error::other(
            "spawned child vanished before its identity could be read",
        ))
    })?;
    // Adopt AFTER the identity read (and after Task-5 resume) so SharedChild's
    // internal try_wait can reap-or-track without losing the identity; the whole
    // Plan-3 wait/kill/identity/pump model is preserved.
    let shared = SharedChild::new(child).map_err(Error::Io)?;

    Ok(Child::from_parts(
        shared,
        id,
        parent_ends,
        kill_on_drop,
        containment,
        attached,
    ))
}

fn build_std_command(cmd: &Command) -> Result<std::process::Command, Error> {
    // Program + args via the Plan-1 quoting model.
    let mut std_cmd = match cmd.input() {
        CommandInput::Empty => return Err(Error::Io(std::io::Error::other("no program specified"))),
        CommandInput::Argv(argv) => {
            let (program, rest) = resolve_program_argv(cmd, argv)?;
            let mut c = std::process::Command::new(program);
            c.args(rest);
            // POSIX: when executable() overrides the loaded file, preserve the
            // user's argv[0] via arg0(). Without this, std would set argv[0] to
            // the executable path, silently dropping the user's intended name.
            #[cfg(unix)]
            if cmd.executable_path().is_some() && !argv.is_empty() {
                use std::os::unix::process::CommandExt;
                c.arg0(&argv[0]);
            }
            c
        }
        CommandInput::CommandLine(line) => build_from_commandline(cmd, line)?,
    };
    // Reject .bat/.cmd (BatBadBut) — only meaningful on Windows.
    reject_batch_script(&std_cmd)?;
    apply_env(&mut std_cmd, cmd.env_ops());
    if let Some(dir) = cmd.cwd() {
        std_cmd.current_dir(dir);
    }
    Ok(std_cmd)
}

// Pick the executable file to load (`executable` overrides argv[0]/first-token).
fn resolve_program(cmd: &Command, fallback: std::ffi::OsString) -> std::ffi::OsString {
    match cmd.executable_path() {
        Some(p) => p.as_os_str().to_os_string(),
        None => fallback,
    }
}

// Program + the trailing args (argv mode). `executable` overrides the loaded
// file; argv[0] is the conventional program name otherwise.
//
// POSIX only: when `executable` is set and argv is non-empty, the user's
// argv[0] is preserved via `CommandExt::arg0` (set on the caller's std_cmd).
// On Windows std has no `arg0`; argv[0] silently becomes the executable path
// (documented limitation lifted in Plan 4's raw backend).
fn resolve_program_argv<'a>(
    cmd: &'a Command,
    argv: &'a [std::ffi::OsString],
) -> Result<(std::ffi::OsString, &'a [std::ffi::OsString]), Error> {
    if argv.is_empty() && cmd.executable_path().is_none() {
        return Err(Error::Io(std::io::Error::other("empty argv")));
    }
    let fallback = if argv.is_empty() {
        std::ffi::OsString::new()
    } else {
        argv[0].clone()
    };
    let program = resolve_program(cmd, fallback);
    let rest = if argv.is_empty() { argv } else { &argv[1..] };
    Ok((program, rest))
}

#[cfg(unix)]
fn build_from_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<std::process::Command, Error> {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    let words = crate::quote::posix::split(line.as_bytes())?;
    // `OsStringExt::from_vec` already yields an OsString; do NOT wrap it in
    // `OsString::from(..)` (that is redundant and fails type inference).
    let argv: Vec<OsString> = words.into_iter().map(OsString::from_vec).collect();
    if argv.is_empty() {
        return Err(Error::Io(std::io::Error::other("empty command line")));
    }
    let program = resolve_program(cmd, argv[0].clone());
    let mut c = std::process::Command::new(program);
    // When executable() overrides the loaded file, argv[0] from the command
    // line is the user's intended name — preserve it via arg0().
    if cmd.executable_path().is_some() {
        use std::os::unix::process::CommandExt;
        c.arg0(&argv[0]);
    }
    c.args(&argv[1..]);
    Ok(c)
}

#[cfg(windows)]
fn build_from_commandline(cmd: &Command, line: &std::ffi::OsString) -> Result<std::process::Command, Error> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::process::CommandExt;
    // Windows is command-line-native. CRITICAL: std::process always PREPENDS a
    // quoted form of the program to lpCommandLine and then appends raw_arg. So
    // raw_arg must be the ARGS portion only (the line MINUS its first token);
    // passing the whole line would duplicate the program token in the child's
    // argv. We split the first token off with first_token_and_rest_wide.
    //
    // Limitation: std has no stable API to set lpApplicationName independently
    // of lpCommandLine. So when executable() is set alongside a commandline(),
    // we explicitly reject the combination rather than silently doing the wrong
    // thing (the child's argv[0] would come from the commandline, but the file
    // loaded would be executable — a confusing mismatch). The raw backend
    // (Plan 4) removes this limitation via direct CreateProcess.
    // TODO(plan4): implement raw backend to support independent executable + commandline on Windows
    if cmd.executable_path().is_some() {
        return Err(Error::Unsupported {
            op: "spawn with executable() and commandline() both set".into(),
            platform: "windows",
            detail: "std::process has no API to set the loaded file independently of \
                     the command line string; use the argv() builder or wait for the \
                     raw backend (Plan 4)"
                .into(),
        });
    }
    let wide: Vec<u16> = line.encode_wide().collect();
    let (first, rest) = crate::quote::windows::first_token_and_rest_wide(&wide)
        .ok_or_else(|| Error::Io(std::io::Error::other("empty command line")))?;
    let program = std::ffi::OsString::from_wide(&first);
    let mut c = std::process::Command::new(program);
    c.raw_arg(std::ffi::OsString::from_wide(&rest)); // args only — program is prepended by std
    Ok(c)
}

fn reject_batch_script(std_cmd: &std::process::Command) -> Result<(), Error> {
    let prog = std::path::Path::new(std_cmd.get_program());
    if let Some(ext) = prog.extension() {
        let ext = ext.to_string_lossy().to_ascii_lowercase();
        if ext == "bat" || ext == "cmd" {
            return Err(Error::Unsupported {
                op: format!("running {}", prog.display()),
                platform: "windows",
                detail: "cmd.exe batch escaping is not implemented (CVE-2024-24576); \
                         use .commandline() to pass an explicit, pre-escaped command line"
                    .into(),
            });
        }
    }
    Ok(())
}

fn apply_env(std_cmd: &mut std::process::Command, ops: &[EnvOp]) {
    for op in ops {
        match op {
            EnvOp::Set(k, v) => {
                std_cmd.env(k, v);
            }
            EnvOp::Remove(k) => {
                std_cmd.env_remove(k);
            }
            EnvOp::Clear => {
                std_cmd.env_clear();
            }
        }
    }
}

// Resolve a non-merge slot to its child-side end + the parent's pipe end (if any).
fn resolve_non_merge(slot: Fd, r: Option<&ResolvedStdio>) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    match r {
        None | Some(ResolvedStdio::Inherit) => Ok((inherit_end(slot)?, None)),
        Some(ResolvedStdio::Null) => Ok((null_end()?, None)),
        Some(ResolvedStdio::File(f)) => Ok((file_end(f)?, None)),
        Some(ResolvedStdio::Pipe(dir)) => make_pipe(*dir),
        Some(ResolvedStdio::Merge(_)) => unreachable!("merge handled in second pass"),
    }
}

fn make_pipe(dir: Direction) -> Result<(ChildEnd, Option<ParentEnd>), Error> {
    let (reader, writer) = std::io::pipe().map_err(Error::Io)?;
    match dir {
        // Child reads: child gets the reader; parent keeps the writer.
        Direction::In => Ok((ChildEnd::from(reader), Some(ParentEnd::Writer(writer)))),
        // Child writes: child gets the writer; parent keeps the reader.
        Direction::Out => Ok((ChildEnd::from(writer), Some(ParentEnd::Reader(reader)))),
    }
}

fn dup(end: &ChildEnd) -> Result<ChildEnd, Error> {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        end.as_fd().try_clone_to_owned().map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        end.as_handle().try_clone_to_owned().map_err(Error::Io)
    }
}

fn null_end() -> Result<ChildEnd, Error> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(if cfg!(windows) { "NUL" } else { "/dev/null" })
        .map_err(Error::Io)?;
    Ok(ChildEnd::from(f))
}

fn file_end(f: &std::fs::File) -> Result<ChildEnd, Error> {
    // Dup the file so the caller's File stays usable.
    let dup = f.try_clone().map_err(Error::Io)?;
    Ok(ChildEnd::from(dup))
}

fn inherit_end(slot: Fd) -> Result<ChildEnd, Error> {
    // Duplicate the parent's matching std stream. Bind the stream to a variable
    // before borrowing its descriptor (a temporary would be dropped while borrowed).
    // For n>=3, Stdio::inherit() has no defined parent stream to dup — reject it
    // explicitly. (The raw backend, Plan 4, can open arbitrary parent fds by number.)
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                s.as_fd().try_clone_to_owned()
            }
            Fd::STDERR => {
                let s = std::io::stderr();
                s.as_fd().try_clone_to_owned()
            }
            other => {
                return Err(Error::Unsupported {
                    op: format!("Stdio::inherit() on {other}"),
                    platform: "unix",
                    detail: "inherit on fd >= 3 has no defined parent stream; \
                             use pipe/file/null, or the raw backend (Plan 4)"
                        .into(),
                })
            }
        };
        owned.map_err(Error::Io)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsHandle;
        let owned = match slot {
            Fd::STDIN => {
                let s = std::io::stdin();
                s.as_handle().try_clone_to_owned()
            }
            Fd::STDOUT => {
                let s = std::io::stdout();
                s.as_handle().try_clone_to_owned()
            }
            _ => {
                let s = std::io::stderr();
                s.as_handle().try_clone_to_owned()
            }
        };
        owned.map_err(Error::Io)
    }
}
