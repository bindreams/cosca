"""Hyper-V host checks for devvm.py, used only when devvm runs on a Windows host.

Vagrant's Hyper-V provider puts the guest on a Hyper-V switch instead of a forwarded port, so the
guarantee "nothing on the host is reachable from the LAN" becomes "the guest sits on an Internal or
Private switch". devvm checks that fail-closed (check_hyperv_host before `up`,
check_hyperv_guest_network right after), and checks the other host prerequisites Vagrant would
otherwise fail on late or with a poor message.

Windows-only calls (ctypes' WinDLL, powershell.exe) live inside functions, so this module imports on
every host: devvm_test.py and devvm_vagrantfiles_test.py run it on Linux in CI. Needs Windows
PowerShell for the Hyper-V cmdlets; there is no other interface to them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import NoReturn

from devvm_common import Guest, dotfile_dir, host_unsupported_reason, vm_name

# Vagrant 2.4.9's `data_dir` for the default machine: <VAGRANT_DOTFILE_PATH>/machines/default/hyperv.
MACHINE_NAME = "default"
SWITCH_NAME = "Default Switch"
SID_ADMINISTRATORS = "S-1-5-32-544"
SID_HYPERV_ADMINISTRATORS = "S-1-5-32-578"
IMAGE_FILE_MACHINE = {"amd64": 0x8664, "arm64": 0xAA64}


def _die(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run_host_powershell(script: str) -> subprocess.CompletedProcess[str]:
    """Run `script` in Windows PowerShell on the host and return the result.

    PSModulePath is dropped so powershell.exe uses its own module directories: a parent
    PowerShell 7 session hands down paths that break Windows PowerShell's module autoload.
    """
    env = {k: v for k, v in os.environ.items() if k.upper() != "PSMODULEPATH"}
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        env=env,
    )


def _token_is_member(sid_string: str) -> bool:
    """Whether the current token has the group `sid_string` enabled (Windows only)."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.ConvertStringSidToSidW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.LPVOID)]
    advapi32.CheckTokenMembership.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(wintypes.BOOL)]
    kernel32.LocalFree.argtypes = [wintypes.LPVOID]

    sid = wintypes.LPVOID()
    if not advapi32.ConvertStringSidToSidW(sid_string, ctypes.byref(sid)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        member = wintypes.BOOL()
        if not advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):
            raise ctypes.WinError(ctypes.get_last_error())
        return bool(member.value)
    finally:
        kernel32.LocalFree(sid)


def can_manage_hyperv() -> bool:
    """Whether the current token is an elevated administrator or in `Hyper-V Administrators`,
    the two cases Vagrant's Hyper-V provider accepts."""
    return _token_is_member(SID_ADMINISTRATORS) or _token_is_member(SID_HYPERV_ADMINISTRATORS)


def native_machine() -> int:
    """The host's native IMAGE_FILE_MACHINE value, correct even for an emulated Python (Windows
    only). platform.machine() reports the emulated architecture instead."""
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT)]
    process_machine = wintypes.USHORT()
    native = wintypes.USHORT()
    if not kernel32.IsWow64Process2(kernel32.GetCurrentProcess(), ctypes.byref(process_machine), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    return native.value


def _nearest_existing(path: Path) -> Path:
    while not path.exists():
        path = path.parent
    return path


def system_full_control_propagates(directory: Path) -> bool:
    """Whether `directory` carries an Allow FullControl ACE for SYSTEM that its children inherit.

    Vagrant's Hyper-V provider refuses to start unless the machine's data directory has that ACE
    as an inherited one (VagrantVM.psm1, Check-VagrantHyperVAccess), so it has to flow down from
    the nearest directory that exists now. NoPropagateInherit would stop it one level down.
    """
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$acl = [System.IO.Directory]::GetAccessControl({_ps_quote(str(directory))}); "
        "$sid = [System.Security.Principal.SecurityIdentifier]; "
        "$ok = @($acl.GetAccessRules($true, $true, $sid) | Where-Object { "
        "$_.IdentityReference.Value -eq 'S-1-5-18' -and "
        "$_.AccessControlType -eq 'Allow' -and "
        "$_.FileSystemRights -eq 'FullControl' -and "
        "($_.InheritanceFlags -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) -and "
        "-not ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) "
        "}).Count -gt 0; "
        "ConvertTo-Json @{ ok = $ok }"
    )
    result = run_host_powershell(script)
    if result.returncode != 0:
        _die(f"could not read the access control list of {directory}:\n{result.stderr}")
    return bool(json.loads(result.stdout)["ok"])


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def check_hyperv_host(guest: Guest) -> None:
    """Exit with a message unless this host can run `guest` on Hyper-V.

    Runs before devvm creates or stages anything. Checks, in order: the guest has a Hyper-V box;
    the host's native architecture matches the guest's; the user may manage Hyper-V; Vagrant's
    data directory will carry the SYSTEM ACE its own access check needs; `Default Switch` exists
    and is Internal or Private, so the guest cannot be bridged onto the LAN.
    """
    reason = host_unsupported_reason(guest)
    if reason is not None:
        _die(f"guest '{guest.name}' is not available on this host: {reason}")

    machine = IMAGE_FILE_MACHINE[guest.arch]
    native = native_machine()
    if native != machine:
        _die(
            f"guest '{guest.name}' is {guest.arch}, but this host's native architecture is "
            f"{_machine_name(native)}; Hyper-V runs only guests of the host's own architecture."
        )

    if not can_manage_hyperv():
        _die(
            "Vagrant's Hyper-V provider needs an elevated administrator or membership in the "
            "'Hyper-V Administrators' group, and this token has neither. Add your account to "
            "'Hyper-V Administrators' (then sign out and in), or run devvm from an elevated shell."
        )

    data_root = _nearest_existing(dotfile_dir(guest))
    if not system_full_control_propagates(data_root):
        _die(
            f"{data_root} does not give SYSTEM an inheritable FullControl entry, which Vagrant's "
            "Hyper-V provider requires on its data directory (its 'Verifying Hyper-V is "
            "accessible' check). Grant it, e.g. from an elevated shell: "
            f'icacls "{data_root}" /grant "SYSTEM:(OI)(CI)F"'
        )

    result = run_host_powershell(
        "$ErrorActionPreference = 'Stop'; "
        f"$s = @(Hyper-V\\Get-VMSwitch | Where-Object {{ $_.Name -eq {_ps_quote(SWITCH_NAME)} }}); "
        "ConvertTo-Json @{ types = @($s | ForEach-Object { $_.SwitchType.ToString() }) }"
    )
    if result.returncode != 0:
        _die(f"could not list Hyper-V switches:\n{result.stderr}")
    types = json.loads(result.stdout)["types"]
    if len(types) != 1:
        _die(
            f"expected exactly one Hyper-V switch named '{SWITCH_NAME}', found {len(types)}. "
            "devvm attaches guests only to that switch and will not let Vagrant pick another."
        )
    if types[0] not in ("Internal", "Private"):
        _die(
            f"the Hyper-V switch '{SWITCH_NAME}' is {types[0]}, not Internal or Private; a guest "
            "on it would be reachable from the LAN."
        )


def _machine_name(machine: int) -> str:
    for name, value in IMAGE_FILE_MACHINE.items():
        if value == machine:
            return name
    return f"machine type {machine:#06x}"


def _recorded_vm_id(guest: Guest) -> str | None:
    """The VM id Vagrant stored for `guest`, or None if no VM has been created yet."""
    id_file = dotfile_dir(guest) / "machines" / MACHINE_NAME / "hyperv" / "id"
    try:
        raw = id_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    except OSError as e:
        _die(f"cannot read the Hyper-V VM id of guest '{guest.name}' ({id_file}): {e}")
    try:
        return str(uuid.UUID(raw))
    except ValueError:
        _die(f"{id_file} does not hold a VM id: {raw!r}")


def vm_id(guest: Guest) -> str:
    """The Hyper-V VM id Vagrant stored for `guest`, validated as a GUID.

    Every operation that changes or opens a VM selects it by this id, never by name.
    """
    recorded = _recorded_vm_id(guest)
    if recorded is None:
        _die(f"no Hyper-V VM id recorded for guest '{guest.name}': it has not been created here")
    return recorded


def check_hyperv_guest_network(guest: Guest) -> None:
    """Exit non-zero if any network adapter of `guest`'s VM is not on an Internal or Private
    switch, after turning that VM off (by id, only it).

    Runs right after `vagrant up` returns, before the first provisioning script. It narrows the
    window the pre-`up` check in check_hyperv_host leaves (the switch changing in between); it
    cannot prevent the VM's first boot.
    """
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"$vm = Hyper-V\\Get-VM -Id {_ps_quote(vm_id(guest))}; "
        "$switches = @(Hyper-V\\Get-VMSwitch); "
        "$bad = @(); "
        "foreach ($a in @(Hyper-V\\Get-VMNetworkAdapter -VM $vm)) { "
        "if (-not $a.SwitchName) { continue }; "
        "$m = @($switches | Where-Object { $_.Name -eq $a.SwitchName }); "
        "if ($m.Count -eq 0 -or @($m | Where-Object { $_.SwitchType.ToString() -notin 'Internal', 'Private' }).Count -gt 0) "
        "{ $bad += $a.SwitchName } }; "
        "if ($bad.Count -gt 0) { Hyper-V\\Stop-VM -VM $vm -TurnOff -Force }; "
        "ConvertTo-Json @{ bad = @($bad) }"
    )
    result = run_host_powershell(script)
    if result.returncode != 0:
        _die(f"could not inspect the network adapters of VM '{vm_name(guest)}':\n{result.stderr}")
    bad = json.loads(result.stdout)["bad"]
    if bad:
        _die(
            f"VM '{vm_name(guest)}' has an adapter on {', '.join(repr(b) for b in bad)}, which is not "
            "an Internal or Private Hyper-V switch, so it could be reachable from the LAN. devvm "
            "turned the VM off before provisioning anything. Check the switch named in "
            f"scripts/devvm/guests/{guest.name}/Vagrantfile, then `devvm.py destroy {guest.name}`."
        )


def vmconnect_argv(guest: Guest) -> list[str]:
    """The command that opens Hyper-V's console (`vmconnect`) on `guest`'s VM, selected by id."""
    return ["vmconnect.exe", "localhost", "-G", vm_id(guest)]


def vmconnect_hint(guest: Guest) -> str:
    """`vmconnect_argv` as text for a message; before the VM exists, says how to get one."""
    recorded = _recorded_vm_id(guest)
    if recorded is None:
        return "Hyper-V's console (`vmconnect.exe`, once `devvm.py up` has created the VM)"
    return f"Hyper-V's console (`vmconnect.exe localhost -G {recorded}`)"


def open_vm_console(guest: Guest) -> None:
    """Open Hyper-V's own console window (`vmconnect`) on `guest`'s VM; does not wait for it."""
    subprocess.Popen(vmconnect_argv(guest))
