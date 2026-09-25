"""Windows-guest lifecycle for devvm.py: provisioning, reboot, licensing, and interactive-
session-wait logic.

Split out of devvm.py (which keeps the CLI/subcommand glue and Linux-guest logic) because
Windows guests are the only guest kind with anything to license, reboot, or wait for a
session about — Linux guests never touch this module. Imports shared primitives (Guest,
run_vagrant, ...) from devvm_common.py rather than from devvm.py itself, so devvm.py can
import this module without an import cycle.

Not meaningfully testable on its own — every function here shells out to vagrant/WinRM and is
only testable inside a real guest; see devvm_test.py's module docstring and scripts/README.md.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Sibling-module import, working whether devvm.py (the only importer of this module) is
# running directly as `__main__` (`uv run scripts/devvm.py ...` puts scripts/ itself on
# sys.path) or loaded as `scripts.devvm` (devvm_test.py's `python -m unittest
# scripts.devvm_test` puts REPO_ROOT on sys.path instead, not scripts/). Inserted
# defensively here too, not just in devvm.py, so this module also imports cleanly if
# something ever imports it before devvm.py has run its own copy of this same snippet.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from devvm_common import (  # noqa: E402
    Guest,
    WINDOWS_PROVISION_DIR,
    get_vagrant_machine_state,
    powershell_quote,
    run_vagrant,
    run_vagrant_streaming,
    run_vagrant_winrm_bounded,
)

# Last output line windows-account-and-uac.ps1 prints, telling devvm.py whether an
# EnableLUA/autologon change it just made needs a reboot to take effect (see
# provision_windows_guest).
REBOOT_MARKER_TRUE = "DEVVM_REBOOT_REQUIRED=1"
REBOOT_MARKER_FALSE = "DEVVM_REBOOT_REQUIRED=0"

# SoftwareLicensingProduct.LicenseStatus: 1 means Licensed. Anything else (5 = Notification is
# what a TIMEBASED_EVAL image reports once its evaluation period elapses, on
# stromweld/windows-10 202503.09.0) means the guest is not currently licensed and needs a
# rearm before it's safe to leave unattended - see ensure_windows_license_current.
WINDOWS_LICENSE_STATUS_LICENSED = 1
# Rearm proactively within this many minutes of the eval period actually running out, not
# just once it's already hit zero - a guest that dies mid-provisioning run (see
# ensure_windows_license_current's docstring for the incident this is fixing) is worse than
# spending a rearm slightly early. One day's buffer is cheap next to the box's eval window
# (on the order of months) and the two rearms this image ships with.
WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES = 24 * 60

# The human-facing failure bound for reboot_windows_guest_and_wait's post-reboot wait and
# wait_for_windows_session's session wait (reused verbatim by provision_windows_guest for `up`
# or `sync`, whenever this invocation started or rebooted the guest): a guest coming back up, or
# a session appearing, is a genuinely
# external event that might never complete, and this is the same already-configured,
# already-real bound the Windows Vagrantfile itself uses (config.vm.boot_timeout /
# config.winrm.timeout, both 3600s in scripts/devvm/guests/windows-x64/Vagrantfile) — not a
# second, uncoordinated guess.
WINDOWS_REBOOT_DEADLINE_SECONDS = 3600


def run_windows_script(
    guest: Guest,
    script_path: Path,
    *,
    elevated: bool = True,
    env: dict[str, str] | None = None,
    display: bool = False,
) -> str:
    """Run a Windows provisioning .ps1 script directly over `vagrant winrm`, instead of
    through Vagrant's WinRM shell provisioner.

    Why: Vagrant's shell provisioner's WinRM path (`provision_winrm` in vagrant 2.4.9's own
    plugins/provisioners/shell/provisioner.rb) calls `@machine.guest.capability(:wait_for_reboot)`
    UNCONDITIONALLY at the very start of every invocation, before it even uploads the script.
    That capability (plugins/guests/windows/cap/reboot.rb, scripts/reboot_detect.ps1) doesn't
    just check for a pending reboot — it actively PROBES for one by running a real
    `shutdown -f -r -t 60` (a genuine 60-second-out forced restart) and then, if nothing was
    already scheduled, immediately `shutdown -a` to cancel it. That is a real, if usually
    aborted-in-time, standing restart fuse on every ordinary provisioning step — confirmed via
    guest System-log event 1074/1075 pairs lining up with `vagrant provision` runs (see
    scripts/README.md's root-cause note). `vagrant winrm -c` never reaches
    that capability — confirmed by reading plugins/commands/winrm/command.rb,
    communicators/winrm/communicator.rb, and communicators/winrm/shell.rb end to end: none of
    them reference `wait_for_reboot` or `reboot_detect` — so driving each script through it
    removes the fuse entirely. `-e`/`--elevated` requests the `winrm-elevated` shell type,
    matching the shell provisioner's `privileged: true` without going anywhere near
    `wait_for_reboot`.

    Uploads the script itself via `vagrant upload` (plain WinRM file transfer, no guest
    process/command line involved) and runs it with `-File`, rather than inlining its content
    as a base64/UTF-16LE `-EncodedCommand`. `-EncodedCommand`'s encoded text becomes part of
    the guest-side `powershell.exe` command line, which Windows' CreateProcess caps at 32767
    chars total - windows-rust.ps1 alone already encodes to a ~25350-char command line,
    comfortably under that limit today but with no margin that's guaranteed to hold as the
    script grows, and no PowerShell-side error if it's ever crossed (CreateProcess just fails
    on the guest). `-File` sidesteps the limit entirely - the
    command line is always the same small, fixed size regardless of script content. The
    upload destination is fixed, dedicated scratch space (C:\\Windows\\Temp), deliberately NOT
    under C:\\cosca-stage/C:\\cosca: windows-clean-stage.ps1 wipes the former and
    windows-mirror-tree.ps1 mirrors-with-deletion into the latter, and either could race an
    upload landing there depending on which script is currently running. Env vars are still
    passed via a `$env:NAME = 'value'; ` prefix ahead of the `-File` invocation, same
    mechanism as before.

    Returns the combined stdout/stderr so callers (e.g. windows-account-and-uac.ps1's
    DEVVM_REBOOT_REQUIRED marker) can scan it. Raises via `run_vagrant_streaming`'s own
    check=True on a nonzero exit (and via `run_vagrant`'s own check=True if the upload itself
    fails).
    """
    guest_script_path = f"C:\\Windows\\Temp\\devvm-{script_path.name}"
    run_vagrant(guest, ["upload", str(script_path), guest_script_path], display=display)
    env_prefix = "".join(f"$env:{name} = {powershell_quote(value)}; " for name, value in (env or {}).items())
    inner = (
        f"{env_prefix}powershell -NoProfile -ExecutionPolicy Bypass "
        f"-File {powershell_quote(guest_script_path)}; exit $LASTEXITCODE"
    )
    args = ["winrm"]
    if elevated:
        args.append("-e")
    args += ["-c", inner]
    _, output = run_vagrant_streaming(guest, args, display=display)
    return output


def set_windows_reboot_marker(guest: Guest) -> None:
    """Create a volatile registry key on the guest — one Windows guarantees does NOT survive a
    reboot (RegistryOptions.Volatile) — as a reboot-detection marker. Call before issuing the
    reboot; reboot_windows_guest_and_wait then polls get_windows_reboot_marker_present for its
    absence.

    Not a LastBootUpTime comparison: this guest's own clock has been observed to jump by hours
    across an ordinary reboot (NTP resync), which would make a wall-clock timestamp comparison
    unreliable in either direction.
    """
    # $ErrorActionPreference='Stop' plus an explicit trap: PowerShell's default
    # ErrorActionPreference is 'Continue', so a failing CreateSubKey (or a failing $k.Close())
    # would not by itself stop the script or make it exit nonzero — `vagrant winrm -c` would
    # then report success even though no marker was ever created, and
    # reboot_windows_guest_and_wait's wait loop would wait out its full deadline for a marker
    # that never existed to begin with, misreporting that as "the guest never rebooted" instead
    # of "the marker was never set." The trap also writes the caught error before exiting: a
    # bare `exit 1` alone would make this fail loudly but silently — `vagrant winrm -c`'s
    # nonzero exit would propagate, but without the error text, there's nothing in run_vagrant's
    # own failure output to say what actually went wrong.
    cmd = (
        "$ErrorActionPreference = 'Stop'; trap { Write-Host \"devvm: $_\"; exit 1 }; "
        "$k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey("
        "'SOFTWARE\\DevvmRebootMarker', $true, [Microsoft.Win32.RegistryOptions]::Volatile); "
        "$k.Close()"
    )
    run_vagrant(guest, ["winrm", "-c", cmd])


def get_windows_reboot_marker_present(guest: Guest, deadline: float) -> tuple[bool | None, str]:
    """Whether set_windows_reboot_marker's key still exists, or None if WinRM isn't answering
    right now (the wait loop treats that as "still waiting", not as an answer either way) —
    paired with the raw WinRM stdout+stderr, so a caller whose deadline expires while still
    getting None can report what the guest was actually saying, not just silence.

    Bounded by `deadline` (a time.monotonic() value, the same one reboot_windows_guest_and_wait
    already computes from WINDOWS_REBOOT_DEADLINE_SECONDS) via run_vagrant_winrm_bounded — see
    its docstring for why a plain `timeout=` isn't safe here.
    """
    result = run_vagrant_winrm_bounded(
        guest,
        "if (Test-Path 'HKLM:\\SOFTWARE\\DevvmRebootMarker') { 'PRESENT' } else { 'ABSENT' }",
        deadline,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    if output == "ABSENT":
        return False, combined_output
    if output == "PRESENT":
        return True, combined_output
    return None, combined_output


def get_windows_autologon_configured(guest: Guest, deadline: float) -> tuple[bool | None, str]:
    """Whether `HKLM:\\...\\Winlogon`'s `AutoAdminLogon` is already `1` on the guest right now,
    or None if WinRM isn't answering or gave an answer that isn't the explicit SET/UNSET this
    prints (the same "don't guess, retry" contract as get_windows_reboot_marker_present) —
    paired with the raw WinRM stdout+stderr, for the same reason.
    windows-account-and-uac.ps1 is the only thing that sets it, and the value persists across
    reboots once set — so this is `True` on any guest that has completed account/UAC
    provisioning at least once, even on an `up` that doesn't run that script again.
    provision_windows_guest uses this to know whether to wait for an interactive session
    before returning, on a guest where autologon was already configured by an earlier `up`.

    Bounded by `deadline` (a time.monotonic() value, the caller's own session-wait deadline) via
    run_vagrant_winrm_bounded — see its docstring for why a plain `timeout=` isn't safe here.
    """
    result = run_vagrant_winrm_bounded(
        guest,
        "if ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' "
        "-Name AutoAdminLogon -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { 'SET' } else { 'UNSET' }",
        deadline,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    if output == "UNSET":
        return False, combined_output
    if output == "SET":
        return True, combined_output
    return None, combined_output


def get_windows_interactive_username(guest: Guest, deadline: float) -> tuple[str | None, str]:
    """The domain-qualified name of the guest's autologon account ("vagrant") if it currently
    has a live interactive logon anywhere, or None if it doesn't yet or WinRM isn't answering —
    paired with the raw WinRM stdout+stderr, for the same reason as
    get_windows_reboot_marker_present. Used by wait_for_windows_session to confirm autologon
    has actually produced a real interactive session — the thing
    windows-run-unelevated.ps1's scheduled task borrows a filtered token from — not just that
    the kernel has finished booting.

    The owner of a running `explorer.exe` (the desktop shell itself) is used rather than
    `Win32_ComputerSystem.UserName` (goes blank the moment an RDP logon takes over the console
    session, even though the account is still genuinely logged in) or
    `Win32_LoggedOnUser`/`Win32_LogonSession` (stays stale after a sign-out instead of
    reflecting it): a live desktop shell needs no logon-type enumeration to be
    session-type-agnostic across console, RDP, and cached logons, and is proof enough of an
    active session on its own. Filtered to the owning account so an explorer.exe belonging to a
    different user already logged onto the same box can't be mistaken for 'vagrant's own
    session.

    devvm.py's cmd_run passes the result of this through as -InteractiveUser to
    windows-run-unelevated.ps1, which used to run this identical WMI query independently — see
    that script's own $currentUser assignment.

    Bounded by `deadline` (a time.monotonic() value) via run_vagrant_winrm_bounded — see its
    docstring for why a plain `timeout=` isn't safe here.
    """
    cmd = (
        "$o = Get-CimInstance -ClassName Win32_Process -Filter \"Name='explorer.exe'\" | "
        "ForEach-Object { Invoke-CimMethod -InputObject $_ -MethodName GetOwner } | "
        "Where-Object { $_.ReturnValue -eq 0 -and $_.User -eq 'vagrant' } | Select-Object -First 1; "
        'if ($o) { "$($o.Domain)\\$($o.User)" }'
    )
    result = run_vagrant_winrm_bounded(guest, cmd, deadline)
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        return None, combined_output
    output = result.stdout.strip()
    return (output or None), combined_output


def _require_guest_running(guest: Guest, deadline: float, *, what: str, last_output: str = "") -> None:
    """Raise if the guest is no longer 'running' per vagrant, or if `deadline` (a
    time.monotonic() value) has passed. Shared by reboot_windows_guest_and_wait's wait loop and
    wait_for_windows_session's wait loop so a powered-off/crashed guest fails immediately
    instead of retrying WinRM forever, and so both loops fail on the same kind of monotonic
    bound (each call site passes its own `deadline`, not necessarily tied to a reboot).

    `last_output`, if given, is the raw stdout+stderr from the loop's most recent WinRM check —
    included in the deadline error so a human debugging a timeout sees what the guest was
    actually saying right before giving up, not just the bare "didn't finish within Ns."
    """
    state = get_vagrant_machine_state(guest)
    if state != "running":
        raise RuntimeError(
            f"devvm: guest '{guest.name}' is no longer 'running' (vagrant status: {state!r}) "
            f"while waiting for {what} — it will not come back on its own; run `devvm.py up` "
            "to bring it back."
        )
    if time.monotonic() >= deadline:
        message = (
            f"devvm: guest '{guest.name}' did not finish {what} within "
            f"{WINDOWS_REBOOT_DEADLINE_SECONDS}s."
        )
        if last_output.strip():
            message += f"\nLast WinRM output:\n{last_output}"
        raise RuntimeError(message)


def wait_for_windows_session(guest: Guest, deadline: float) -> None:
    """Block until the guest reports a real interactive (autologon) session on the console
    (session 1) — the thing windows-run-unelevated.ps1's scheduled task needs to borrow a
    filtered token from — or `deadline` (a time.monotonic() value) passes.

    A reboot's own marker clearing as soon as the kernel finishes booting can still be ahead
    of autologon actually producing that session. Callers that know a session is coming (a
    reboot that just configured autologon, or a guest that already has autologon configured)
    call this explicitly instead of letting the next unelevated probe race it.

    No `time.sleep()`: each iteration is a real WinRM round-trip, and failure just means "ask
    again immediately," not "nap, then ask again." Bounded by `deadline` and by
    `_require_guest_running` failing fast the moment `vagrant status` reports the guest isn't
    running any more.
    """
    last_output = ""
    while True:
        _require_guest_running(
            guest, deadline, what="an interactive (autologon) session", last_output=last_output
        )
        username, last_output = get_windows_interactive_username(guest, deadline)
        if username is not None:
            return


def reboot_windows_guest_and_wait(guest: Guest) -> None:
    """Issue a real guest reboot ourselves and block until the guest reports the reboot
    actually happened: set_windows_reboot_marker's marker, set before the reboot, has gone
    missing after it.

    Says nothing about sessions. A reboot completing is not the same as autologon having
    produced a real interactive session on top of it — callers that need one call
    wait_for_windows_session themselves afterward, under their own deadline.
    provision_windows_guest calls wait_for_windows_session conditionally — only when this
    invocation started or rebooted the guest (and, even then, only if
    get_windows_autologon_configured says autologon is set) — once, at the end of its own
    provisioning flow. See provision_windows_guest's own comment for why only that invocation,
    not merely "autologon is configured" or `create`, is the right gate.

    Deliberately does NOT go through Vagrant's named `reboot-if-needed` shell provisioner /
    `Reboot.reboot` capability: that path is itself a shell provisioner, so it still runs
    through `provision_winrm`'s unconditional `wait_for_reboot` fuse first, and its own
    `wait_for_reboot` wait loop (plugins/guests/windows/cap/reboot.rb) is a `sleep 10` poll on
    top of that same reboot_detect.ps1 probe. Issuing `shutdown /r` directly (the same command
    `Reboot.reboot` itself runs, confirmed by reading cap/reboot.rb) and then waiting for the
    reboot marker to clear avoids both.

    `shutdown /r /t 0`'s own exit code is NOT trusted as a pass/fail signal: a `/t 0` shutdown
    tears down the guest (and its WinRM connection) essentially immediately, so `vagrant winrm`
    can report a nonzero exit purely because the connection dropped out from under it
    mid-response — not because the reboot failed to schedule. The
    wait loop below is the real check that the reboot actually happened; a nonzero exit here
    is logged but does not abort early on its own.

    No `time.sleep()`, and no chosen retry interval of devvm.py's own: each iteration IS the
    wait — a real WinRM round-trip or a real `vagrant status` query — and failure just means
    "ask again immediately," not "nap, then ask again." The loop is bounded by one monotonic
    deadline (WINDOWS_REBOOT_DEADLINE_SECONDS, reusing the Windows Vagrantfile's own 3600s
    boot_timeout/winrm.timeout — a real, already-configured, human-facing failure bound for a
    guest reboot genuinely never completing) and by `_require_guest_running` failing fast the
    moment `vagrant status` reports the guest isn't running any more, instead of retrying
    `vagrant winrm` in a tight loop against a guest that is never answering again (a powered-off
    or crashed guest would otherwise burn a host core forever, since `vagrant winrm` itself has
    no readiness wait — see get_windows_reboot_marker_present's docstring).
    """
    set_windows_reboot_marker(guest)
    print(f"+ rebooting guest '{guest.name}' directly (shutdown /r) and waiting for the reboot marker to clear", file=sys.stderr)
    returncode = run_vagrant(guest, ["winrm", "-c", 'shutdown /r /t 0 /f /d p:4:1 /c "devvm reboot"'], check=False)
    if returncode != 0:
        print(
            f"devvm: `vagrant winrm` reported a nonzero exit ({returncode}) issuing the "
            f"reboot on guest '{guest.name}' — with `/t 0` that's expected even on a "
            "successfully-scheduled reboot, since the connection drops out from under it "
            "almost immediately. Proceeding to wait for the reboot marker to clear, which is "
            "the actual check.",
            file=sys.stderr,
        )

    deadline = time.monotonic() + WINDOWS_REBOOT_DEADLINE_SECONDS
    last_output = ""
    while True:
        _require_guest_running(
            guest, deadline, what="the reboot marker to clear", last_output=last_output
        )
        present, last_output = get_windows_reboot_marker_present(guest, deadline)
        if present is False:
            return


def get_windows_license_state(guest: Guest) -> tuple[int, float, int]:
    """Read the guest's Windows license status via WMI/CIM: (LicenseStatus,
    GracePeriodRemaining in minutes, RemainingWindowsReArmCount).

    Reads the same underlying data `slmgr.vbs /dlv` prints, but structured: no parsing of
    slmgr's free-text human-readable output, just the WMI properties behind it
    (SoftwareLicensingProduct for the active product entry - the one with a non-null
    PartialProductKey - and SoftwareLicensingService for the rearm counter).
    """
    cmd = (
        "$p = Get-CimInstance SoftwareLicensingProduct | "
        "Where-Object { $_.PartialProductKey } | Select-Object -First 1; "
        "$s = Get-CimInstance SoftwareLicensingService; "
        'Write-Host ("DEVVM_LICENSE_STATUS=" + $p.LicenseStatus); '
        'Write-Host ("DEVVM_LICENSE_GRACE_MINUTES=" + $p.GracePeriodRemaining); '
        'Write-Host ("DEVVM_LICENSE_REARM_REMAINING=" + $s.RemainingWindowsReArmCount)'
    )
    _, output = run_vagrant_streaming(guest, ["winrm", "-c", cmd])
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line and line.split("=", 1)[0] in (
            "DEVVM_LICENSE_STATUS",
            "DEVVM_LICENSE_GRACE_MINUTES",
            "DEVVM_LICENSE_REARM_REMAINING",
        ):
            key, value = line.split("=", 1)
            values[key] = value.strip()
    try:
        return (
            int(values["DEVVM_LICENSE_STATUS"]),
            float(values["DEVVM_LICENSE_GRACE_MINUTES"]),
            int(values["DEVVM_LICENSE_REARM_REMAINING"]),
        )
    except (KeyError, ValueError) as e:
        raise RuntimeError(
            f"devvm: could not read guest '{guest.name}' Windows license state via WMI - "
            f"missing or unparsable marker(s) in output ({e}):\n{output}"
        ) from e


def ensure_windows_license_current(guest: Guest, *, display: bool = False) -> bool:
    """Rearm the guest's time-based Windows evaluation license if it's expired or within
    WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES of expiring, then reboot for the rearm to take effect.

    Returns whether it rebooted the guest — provision_windows_guest seeds its own `rebooted`
    from this, so the license-rearm reboot (this function's own, distinct from the
    windows-account-and-uac.ps1 reboot, which can still set `rebooted = True` again later) also
    counts toward the post-provisioning session-wait gate instead of being invisible to it.

    Why this exists: the stromweld/windows-10 box's eval image self-terminates once its
    evaluation period elapses - the Windows License Manager Service (wlms.exe) issues a
    genuine guest-initiated ACPI power-off (System event log ID 1074), not a devvm.py/cosca
    command or a crash, ending the whole QEMU process with only a few seconds' warning. It has
    taken the guest down mid-provisioning.

    Runs on every `up` (create is always True in devvm.py's cmd_up's own call into
    provision_windows_guest - `vagrant up` is itself idempotent, so this runs whether the guest
    is being created for the first time or merely started again), not on every `sync` -
    because Windows evaluation rearms are a limited, consumable resource (this image ships
    with 2), not something to spend on every provisioning pass; `sync` (create=False) never
    reaches this function at all.

    Direct `vagrant winrm -c` (no `-e`/elevated shell) is enough for `slmgr /rearm`, the same
    as `reboot_windows_guest_and_wait`'s `shutdown /r`: this box already hands WinRM sessions a
    full, unfiltered High-integrity token (LocalAccountTokenFilterPolicy=1 - see devvm.py's
    cmd_run comment on the same fact), so no separate elevation request is needed for a
    privileged operation issued over WinRM.
    """
    status, grace_minutes, rearm_remaining = get_windows_license_state(guest)
    needs_rearm = status != WINDOWS_LICENSE_STATUS_LICENSED or grace_minutes < WINDOWS_LICENSE_NEAR_EXPIRY_MINUTES
    if not needs_rearm:
        print(
            f"note: guest '{guest.name}' Windows evaluation license is current "
            f"(status={status}, grace={grace_minutes:.0f}min) - no rearm needed.",
            file=sys.stderr,
        )
        return False
    if rearm_remaining <= 0:
        print(
            f"error: guest '{guest.name}' Windows evaluation license is expired or near "
            f"expiry (status={status}, grace={grace_minutes:.0f}min) and has 0 rearms "
            "remaining - the box's evaluation can no longer be extended; use a newer box.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"note: guest '{guest.name}' Windows evaluation license is expired or near expiry "
        f"(status={status}, grace={grace_minutes:.0f}min, {rearm_remaining} rearm(s) "
        "remaining) - running slmgr /rearm and rebooting for it to take effect.",
        file=sys.stderr,
    )
    run_vagrant(guest, ["winrm", "-c", "cscript.exe //nologo C:\\Windows\\System32\\slmgr.vbs /rearm"], display=display)
    # Session-waiting, if needed, happens once at the end of provision_windows_guest (via this
    # function's return value, ORed into that gate) — this reboot can run before
    # windows-account-and-uac.ps1 has ever configured autologon, on a genuinely fresh box, so
    # waiting for a session here unconditionally could hang the full
    # WINDOWS_REBOOT_DEADLINE_SECONDS for no reason.
    reboot_windows_guest_and_wait(guest)
    new_status, new_grace_minutes, _ = get_windows_license_state(guest)
    if new_status != WINDOWS_LICENSE_STATUS_LICENSED:
        print(
            f"error: guest '{guest.name}' Windows evaluation license still not current after "
            f"rearm and reboot (status={new_status}, grace={new_grace_minutes:.0f}min) - the "
            "rearm did not take effect as expected. This is a bug (or the box's own rearm "
            "budget silently didn't reset), not something to proceed past.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(
        f"note: guest '{guest.name}' Windows evaluation license rearmed successfully "
        f"(status={new_status}, grace={new_grace_minutes:.0f}min).",
        file=sys.stderr,
    )
    return True


def should_wait_for_session(*, started_guest: bool, rebooted: bool) -> bool:
    """Whether provision_windows_guest's own invocation just produced a fresh boot, and so
    should wait for a real interactive (autologon) session before returning — see that
    function's session-wait comment for the full reasoning (AutoAdminLogon only fires a fresh
    logon at boot; merely "autologon is configured" is not itself such an event). Pulled out as
    its own pure function so this decision has a unit test independent of a live guest.
    """
    return started_guest or rebooted


def provision_windows_guest(guest: Guest, *, auto_consent: bool, display: bool = False, create: bool) -> None:
    """Create (if `create`) and/or provision a Windows guest, driving each provisioning
    script directly over `vagrant winrm` (see run_windows_script) instead of Vagrant's WinRM
    shell provisioner — see that function's docstring for why.

    Order matches the original Vagrantfile-declared provisioner order exactly, since later
    steps depend on earlier ones: windows-clean-stage.ps1 must run before the "file"
    provisioner (still Vagrant-driven — plugins/provisioners/file/provisioner.rb is confirmed
    clean of any wait_for_reboot call, so there's no reason to reimplement WinRM file upload
    by hand) re-populates C:\\cosca-stage; windows-mirror-tree.ps1 and windows-lock-tree.ps1
    depend on that upload; windows-account-and-uac.ps1 and windows-rust.ps1 are independent of
    each other but both come last, matching the original order (rust installs before the
    reboot-required check, same as before this refactor).

    The license-rearm check (create only) runs before every other provisioning step,
    including windows-clean-stage.ps1: an expired-eval shutdown can land mid-step regardless
    of which step it is (it has hit during windows-lock-tree.ps1), so there's
    no later step that's actually safer to run first - checking immediately, before spending
    any time on the rest, is strictly better than finding out partway through.
    """
    # Whether THIS invocation is the one that actually started the guest (as opposed to `up`
    # finding it already running and doing nothing) — see the session-wait gating at the
    # bottom of this function for why that distinction, not merely `create`, is what matters.
    started_guest = False
    # Set from ensure_windows_license_current's return value below (create only), so a reboot
    # the license rearm causes counts toward the session-wait gate exactly like the
    # windows-account-and-uac.ps1 reboot does.
    rebooted = False
    if create:
        started_guest = get_vagrant_machine_state(guest) != "running"
        # --no-provision: a fresh `up` would otherwise auto-run the one remaining
        # Vagrantfile-declared provisioner (the "file" upload) as part of creation, and then
        # the explicit `vagrant provision` call two lines down would run it a second,
        # redundant time. Skipping it here makes exactly one invocation happen either way
        # (create or not), driven explicitly below.
        run_vagrant(guest, ["up", "--provider", "qemu", "--no-provision"], display=display)
        rebooted = ensure_windows_license_current(guest, display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-clean-stage.ps1", elevated=True, display=display)
    # The lone remaining Vagrantfile-declared provisioner: uploads the staged tree into
    # C:/cosca-stage. `run: "always"` on it means a plain `vagrant provision` re-runs it every
    # time, same as before this refactor.
    run_vagrant(guest, ["provision"], display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-mirror-tree.ps1", elevated=True, display=display)
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-lock-tree.ps1", elevated=True, display=display)
    account_output = run_windows_script(
        guest,
        WINDOWS_PROVISION_DIR / "windows-account-and-uac.ps1",
        elevated=True,
        display=display,
        env={"DEVVM_WINDOWS_AUTO_CONSENT": "1" if auto_consent else "0"},
    )
    run_windows_script(guest, WINDOWS_PROVISION_DIR / "windows-rust.ps1", elevated=False, display=display)

    if REBOOT_MARKER_TRUE in account_output:
        print(
            "note: an EnableLUA or autologon change needs a reboot to take effect — "
            "rebooting the guest now directly (devvm.py-driven; see reboot_windows_guest_and_wait, "
            "not Vagrant's wait_for_reboot fuse).",
            file=sys.stderr,
        )
        reboot_windows_guest_and_wait(guest)
        rebooted = True
    elif REBOOT_MARKER_FALSE not in account_output:
        print(
            "error: windows-account-and-uac.ps1 did not print a DEVVM_REBOOT_REQUIRED "
            "marker — can't tell whether a reboot is needed, so refusing to guess. This is a "
            "bug in the provisioner script, not something to silently proceed past.",
            file=sys.stderr,
        )
        sys.exit(1)

    # A real interactive (autologon) session may not exist yet the moment this returns, and
    # windows-run-unelevated.ps1's scheduled task needs one to borrow a filtered token from —
    # but AutoAdminLogon (without ForceAutoLogon, which this tool does not set) only fires a
    # fresh logon at BOOT. So waiting for one is only ever correct when THIS invocation is what
    # just produced a boot: either it started the guest itself (`started_guest`, only ever True
    # under `create`) or it rebooted the guest — via the license rearm above (create-only) or via
    # the windows-account-and-uac.ps1 reboot just above, which `sync` can trigger too
    # (create=False): that script re-runs on every `sync`, and can still decide a reboot is
    # needed. Merely "autologon is configured" (true on every subsequent `up`/`sync` once
    # windows-account-and-uac.ps1 has ever succeeded, regardless of whether a human RDP'd in and
    # signed out since) is not such an event — waiting on that alone would block for up to
    # WINDOWS_REBOOT_DEADLINE_SECONDS for a session that will not spontaneously reappear.
    # `run --unelevated` needs no proactive wait either — devvm.py's cmd_run's own
    # get_windows_interactive_username call already fails immediately when there is no session
    # to borrow.
    #
    # No `create` gate: `sync` (create=False) can also reboot the guest via
    # windows-account-and-uac.ps1, and needs the same wait `up` does.
    if should_wait_for_session(started_guest=started_guest, rebooted=rebooted):
        # A None (WinRM not answering this particular check yet, even though every script above
        # just succeeded over it) is retried, not guessed at or treated as fatal on the first
        # occurrence — the same "ask again immediately, fail only once the guest is gone or the
        # deadline passes" contract wait_for_windows_session and reboot_windows_guest_and_wait's
        # own loops use, via the same _require_guest_running and one shared deadline (also
        # reused below for wait_for_windows_session itself, if it turns out to be needed).
        deadline = time.monotonic() + WINDOWS_REBOOT_DEADLINE_SECONDS
        last_output = ""
        while True:
            _require_guest_running(
                guest, deadline, what="a readable autologon-configured state", last_output=last_output
            )
            autologon_configured, last_output = get_windows_autologon_configured(guest, deadline)
            if autologon_configured is not None:
                break
        if autologon_configured:
            print(
                "+ this run just started or rebooted the guest — waiting for vagrant's "
                "autologon session to come up (needed by `run --unelevated`), up to "
                f"{WINDOWS_REBOOT_DEADLINE_SECONDS}s. If this hangs: there is no vagrant desktop "
                "session (or WinRM isn't answering) — RDP in as vagrant, or reboot the guest to "
                "force a fresh autologon.",
                file=sys.stderr,
            )
            wait_for_windows_session(guest, deadline)
