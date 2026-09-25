# devvm — throwaway VMs for local system-affecting tests

cosca's subject matter — elevation, cgroups, Windows Job Objects, process trees — means its
most interesting tests change real system state: cgroups and cgroup leaves, Job Objects,
elevation and `ShellExecuteEx`, process trees, process-group signals, `pidfd`/`kqueue` waits
and reaping all reach outside a single process. **Those tests must never run against your own
machine.** `scripts/devvm.py` provisions throwaway VMs for that purpose, so the blast radius
of a scratch script bug is a disposable VM, not your laptop.

This is developer tooling, not shipped code and not a CI replacement — CI keeps the
regression probes; this is for the tests CI structurally cannot run (see
[Windows guests](#windows-guests) below).

## Prerequisites

Install on the host yourself — this tool does not install anything for you:

- [QEMU](https://www.qemu.org/): `brew install qemu`
- [Vagrant](https://www.vagrantup.com/): `brew install --cask hashicorp-vagrant` (the
  Homebrew cask; the Vagrant.app installer works too)
- The [vagrant-qemu](https://github.com/ppggff/vagrant-qemu) plugin, pinned to exactly the
  version `fix_qemu_loopback_only.rb` is verified against (see that file's own comment for
  why an "equivalent" provider or a different version isn't a safe substitute here):
  `vagrant plugin install vagrant-qemu --plugin-version 0.6.3`
- `rsync` (ships with macOS)
- [`uv`](https://docs.astral.sh/uv/): `brew install uv` — runs `devvm.py` without a separate
  install step

Verify with `vagrant plugin list` (expect `vagrant-qemu`) and
`qemu-system-x86_64 --version` / `qemu-system-aarch64 --version`.

## Usage

```sh
uv run scripts/devvm.py list
uv run scripts/devvm.py up linux-x64
uv run scripts/devvm.py run linux-x64 -- cargo --version
uv run scripts/devvm.py ssh linux-x64
uv run scripts/devvm.py sync linux-x64      # after local changes, before the next `run`
uv run scripts/devvm.py halt linux-x64      # shut down, keep the disk
uv run scripts/devvm.py destroy linux-x64   # delete the VM and its state entirely
```

`run` executes one command; anything after `--` is passed through verbatim, e.g.:

```sh
uv run scripts/devvm.py run linux-x64 -- cargo test --features pty
```

Always `destroy` (or at least `halt`) guests you're done with — nothing here auto-expires a
running VM.

## Guests

| Guest           | Box                                    | Provider arch | Host arch it's native on |
| --------------- | -------------------------------------- | ------------- | ------------------------ |
| `linux-x64`     | `generic/ubuntu2204` (qemu, amd64)     | x86-64        | x86-64                   |
| `linux-arm64`   | `perk/ubuntu-2204-arm64` (qemu, arm64) | arm64         | arm64 (Apple Silicon)    |
| `windows-x64`   | `stromweld/windows-10` (qemu, amd64)   | x86-64        | x86-64                   |
| `windows-arm64` | _(none — see below)_                   | —             | —                        |

Both Linux boxes run Ubuntu 22.04; systemd 249 there defaults to the unified cgroup v2
hierarchy, which is why they're the guests for cosca's cgroup lanes.

On the emulated architecture, QEMU falls back to TCG (software emulation) instead of
HVF/KVM, which is dramatically slower — see [Windows guests](#windows-guests) for measured
numbers on this host.

### `windows-arm64`

No publicly available Vagrant box for Windows on arm64 targets the `qemu` or `libvirt`
provider this tool uses. Checked 2026-09-23 on Vagrant Cloud: `hbsmith/win11-arm`,
`pipegz/Windows11ARM`, `nullx/windows-arm64`, `aihua/windows-11-arm64`,
`apter-tech/windows-11-arm64`, `chicken-wire/windows-11-arm64-flutter-dev`,
`santiago-bassett/windows-11-pro-arm64-vmware`, and `Sy3Omda/Win-SRV-2025` — every one of
them publishes only `parallels`, `vmware_desktop`, or `utm` providers, none of which
vagrant-qemu (or plain libvirt) can consume. `devvm.py` refuses this guest with that
explanation rather than silently doing nothing useful.

If you need this lane: build a qcow2 image yourself from a Windows-on-ARM evaluation VHDX
(Microsoft ships these for Windows 11 ARM64) and point `qe.image_path` at it in a new
`scripts/devvm/guests/windows-arm64/Vagrantfile` (see the vagrant-qemu README's "local
qcow2" example) — this tool has no automation for that conversion.

### Windows guests

**Licensing.** `stromweld/windows-10` is a "vanilla Windows 10" box built with
[Bento](https://github.com/chef/bento) from Microsoft's free evaluation media. Evaluation
Windows installs activate on a timer and _expire_ (Windows 10 Enterprise eval is commonly
90 days from the image's build date) — and expiry is not benign: measured directly
(2026-09-24), once the eval period elapses `wlms.exe` (Windows License Manager Service,
running as `NT AUTHORITY\SYSTEM`) issues a real ACPI shutdown on its own (guest System-log
event 1074, "The license period for this installation of Windows has expired. The
operating system is shutting down."), which takes the whole QEMU process down with it —
mid-provisioning, if that's when it fires, with no crash report on the host side.

`devvm.py up` guards against this itself: on every `up` (not on `sync` or a plain
`provision` against an existing guest, which never reach this check — evaluation rearms are
a limited, consumable resource, not something to spend every pass), before any other
provisioning step, it reads
the guest's license state via WMI (`SoftwareLicensingProduct.LicenseStatus`/
`GracePeriodRemaining`, `SoftwareLicensingService.RemainingWindowsReArmCount` —
`get_windows_license_state`/`ensure_windows_license_current` in `scripts/devvm.py`; no
parsing of `slmgr`'s free-text output). If the license is expired or within a day of
expiring, it runs `slmgr /rearm` and reboots (via `reboot_windows_guest_and_wait`) for the
rearm to take effect, then re-checks via WMI and fails loudly if the license still isn't
current. `stromweld/windows-10` 202503.09.0 ships with 2 rearms; once those are spent,
`devvm.py` refuses to proceed with a clear error rather than silently leaving a guest that
can die mid-run — at that point the fix is bumping `config.vm.box_version` in
`scripts/devvm/guests/windows-x64/Vagrantfile` to a newer build, not disabling activation
checks. This is throwaway dev tooling; don't rely on this VM outliving a single
investigation.

**No Vagrant shell provisioner — a real restart fuse, removed.** `windows-x64`'s Vagrantfile
declares exactly one provisioner (the WinRM `file` upload). Every other Windows provisioning
step (`windows-clean-stage.ps1`, `windows-mirror-tree.ps1`, `windows-lock-tree.ps1`,
`windows-account-and-uac.ps1`, `windows-rust.ps1`) is driven directly by `devvm.py` over
`vagrant winrm` (`provision_windows_guest`/`run_windows_script` in `scripts/devvm.py`), not
through Vagrant's `config.vm.provision "shell", ...`. This was a deliberate fix, not a style
choice: vagrant 2.4.9's shell-provisioner WinRM path (`provision_winrm`) calls the guest's
`wait_for_reboot` capability **unconditionally**, at the start of every single shell-
provisioner invocation, before it even uploads the script. That capability's actual "is a
reboot pending?" test (`reboot_detect.ps1`, vendored inside the `vagrant` gem) doesn't just
check — it _schedules a real forced restart_ (`shutdown -f -r -t 60`) and then, if nothing was
already pending, immediately cancels it (`shutdown -a`). That's a genuine, if normally
self-cancelled, 60-second restart fuse on every ordinary `up`/`sync`, once per shell
provisioner that used to be declared here. Measured directly (2026-09-24): every
`vagrant provision` against this guest produced a matching guest System-log event 1074
("wininit.exe has initiated restart") followed by event 1075 ("aborted") — the owner watching
the guest's console twice saw the real "you're about to be signed out" sign-off splash flash
during an otherwise-ordinary `devvm.py sync`, which is exactly what a scheduled-then-cancelled
restart looks like from the console. `vagrant winrm -c` (with or without `-e`/`--elevated`)
never reaches that capability — confirmed by reading vagrant's
`plugins/commands/winrm/command.rb` and `plugins/communicators/winrm/{communicator,shell}.rb`
end to end — so driving each script that way removes the fuse entirely. The one legitimate
reboot this guest ever needs (`EnableLUA`/autologon changes only take effect at the next boot)
is issued and waited on directly by `reboot_windows_guest_and_wait` in `scripts/devvm.py`
(a real `shutdown /r`, then a bounded wait for the guest to report a new boot time and then a
real interactive/autologon session on top of it — no `sleep`, no arbitrarily-chosen poll
interval, just an immediate retry, bounded by `vagrant status` failing fast the moment the
guest stops running and by one overall wall-clock deadline reusing the Vagrantfile's own
3600s `boot_timeout`/`winrm.timeout`), not Vagrant's own `reboot-if-needed`/`Reboot.reboot`
capability, which carries the exact same fuse plus its own `sleep 10` wait loop. `vagrant
winrm -c` itself has no readiness wait of its own (same source read as above), which is why
this wait loop needs its own deadline rather than relying on one baked into `vagrant winrm`.

Whether this fuse explains any _specific_ historical "QEMU just disappeared" failure during
`devvm.py run windows-x64 --unelevated` is **inferred, not measured**: `run`'s own code path
(`vagrant winrm -c`) never touched `wait_for_reboot` either, before or after this fix, so a
death during `run` itself isn't directly this mechanism. But every `up`/`sync` immediately
before such a `run` — which is the normal workflow — did carry this fuse (one scheduled+
aborted restart per shell provisioner, five per pass), so a leftover or mistimed abort from
that immediately-preceding provisioning pass is a plausible contributing cause for a guest
that goes away with no crash report shortly after. No specific historical failure was
correlated against a specific event-1074 timestamp to confirm this; it's a plausible
mechanism, not a demonstrated one.

**Account and UAC.** The box's default `vagrant` account is an ordinary `Administrators`
member — not the built-in Administrator (SID ending `-500`), which Windows elevates
_without_ a UAC prompt regardless of settings. Every `up`/`provision` run verifies this (and
fails loudly, not silently, if it's ever untrue) and resets UAC (`EnableLUA`) to on, via
`scripts/devvm/provision/windows-account-and-uac.ps1`.

By default, `runas` elevation prompts for consent exactly like a real desktop
(`ConsentPromptBehaviorAdmin=5`, the Windows default). For unattended probe runs where a
human isn't there to click through the prompt, pass `--allow-elevation` to `up`:

```sh
uv run scripts/devvm.py up windows-x64 --allow-elevation
```

This sets `ConsentPromptBehaviorAdmin=0` (auto-approve, still logged, UAC still nominally
on) — **opt-in only**, never the default, and the tool prints a note every time it's active.

**Headless by default, and how `run --unelevated` measures the real UAC path anyway.** The
guest boots with no display (`-display none`, vagrant-qemu's default) and is normally reached
over WinRM/PowerShell remoting. A WinRM session is a network logon in session 0 with (this
box has `LocalAccountTokenFilterPolicy=1`) a full, unsplit High-integrity token — so a probe
run over plain `devvm.py run`/`ssh` that calls `ShellExecuteExW("runas")` already has full
rights and elevates trivially, measuring elevated-to-elevated, not the real desktop
unelevated-user-clicks-through-UAC path this guest exists to probe.

`devvm.py run <guest> --unelevated -- <cmd>` (Windows only) measures the real path instead,
with no display or UI automation needed: `scripts/devvm/provision/windows-account-and-uac.ps1`
configures the `vagrant` account to autolog in at boot, giving the guest a genuine active
interactive (session 1, console) logon; `windows-run-unelevated.ps1` then runs the command via
a scheduled task (`Register-ScheduledTask` with a `New-ScheduledTaskPrincipal -LogonType
Interactive -RunLevel Limited` principal — the PowerShell cmdlets replaced an earlier
`schtasks.exe`-based version of this script), which borrows that logon's actual filtered token
at the LIMITED (non-elevated) run level even though the account is itself an Administrators
member.
Combined with `--allow-elevation` (`ConsentPromptBehaviorAdmin=0`), a `runas` child launched
from that probe takes the consent path with no click required. Verify this is measuring what
it claims to by running the probe's own integrity check:

```sh
uv run scripts/devvm.py run windows-x64 --unelevated -- whoami /groups
```

Look for `Mandatory Label\Medium Mandatory Level` in the output — that's the unelevated probe
itself, not a `runas` child. To confirm a `runas`-elevated child of that probe actually reaches
High integrity, run the same command against a script that shells out via `runas`/
`ShellExecuteEx` and checks its own `whoami /groups`; look for `Mandatory Label\High Mandatory
Level` in its output instead.

**A `--unelevated` command that itself starts `powershell.exe` is fine — the wrapper already
routes around a PowerShell 5.1 quirk for you.** PowerShell 5.1 parses a native child's stderr
through its own stream reader regardless of the redirection operator used (`*>`, `2>&1`, even a
plain `2>` alone) or `-OutputFormat`, and treats a `#< CLIXML` prefix (written by a nested
non-interactive powershell.exe with redirected output) as serialized records to deserialize —
throwing `Cannot process the XML from the 'Error' stream of '...': Data at the root level is
invalid` if what follows isn't well-formed CLIXML. `windows-run-unelevated.ps1` avoids this by
running its direct child via `Start-Process -RedirectStandardOutput ... -RedirectStandardError
...`: those are real OS-level file handles, so PowerShell's stream reader never sees the
stream. If you write your own variant of this wrapper, or invoke `powershell.exe`/`pwsh.exe` as
a direct child of another PowerShell process elsewhere in this tooling, use the same
`Start-Process` redirection rather than any PowerShell redirection operator.

If a probe genuinely needs a human (or UI automation) to see and answer the secure-desktop
prompt itself — rather than just observing its outcome — give the guest a display instead:

```sh
uv run scripts/devvm.py up windows-x64 --display
```

This opens a real, local QEMU window on this Mac (`-display cocoa -vga std`) — not VNC or any
other network-exposed display, so it doesn't touch the loopback-only port-forwarding guarantee
above. Off by default; pass it again on every `up` that needs it (not persisted). RDP into the
guest is the other option if a window on this Mac specifically isn't what's needed.

**Measured timings on this host** (Apple Silicon Mac, so `windows-x64` runs under TCG
cross-arch emulation; one-time data point on 2026-09-23, not a guarantee):

| Guest                      | `up` (import → provisioned)                                                                                                                                                    | trivial command | `destroy` |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- | --------- |
| `linux-arm64` (native HVF) | ~75s                                                                                                                                                                           | <1s             | ~5s       |
| `windows-x64` (TCG)        | ~13.5 min (import + first boot + WinRM ready + full provisioning: file upload plus the 5 devvm.py-driven scripts — clean-stage, mirror-tree, lock-tree, account-and-uac, rust) | ~30s            | ~1 min    |

`windows-x64`'s `boot_timeout`/`winrm.timeout` are set to 3600s to give real headroom for a
slower host or a colder box cache; in practice first boot under TCG on this host landed
nowhere near that ceiling.

## Read-only working tree

`up` and `sync` get a copy of the working tree into the guest without letting the guest write
back into your actual source tree. The copy is an allow-list, not an exclude-list: it's exactly
the files `git ls-files` reports as tracked, filtered to those that still exist on disk — so
untracked files (`CLAUDE.local.md`, `.claude/`, build output, etc.) and `.git` itself never
reach the guest, without needing to enumerate what to leave out.

- **Linux guests** (`linux-x64`, `linux-arm64`): a one-shot `rsync` push to
  `~/cosca`, files landing mode `444` (directories stay `755` so later syncs can still
  add/remove files). This is `vagrant`'s built-in `rsync` synced-folder type, not a live
  mount — the guest never writes through to the host.
- **Windows guest** (`windows-x64`): no rsync binary on the box, and Vagrant's SMB synced
  folder needs a one-time macOS _System Settings → Sharing → File Sharing_ toggle plus a
  password prompt on every mount — too much friction for a throwaway VM. Instead, the pipeline
  is four steps, always run in this order (see [Windows guests](#windows-guests) above for why
  only the second is an actual Vagrant provisioner, not a `devvm.py`-driven `vagrant winrm`
  call): `windows-clean-stage.ps1` wipes the guest's scratch staging directory
  (`C:\cosca-stage`); Vagrant's `file` provisioner uploads `scripts/devvm.py sync`'s host-side
  staged copy (`.tmp/devvm/windows-x64/tree/`, see above) into that staging directory over
  WinRM; `windows-mirror-tree.ps1` robocopy-`/MIR`s it from there into `C:\cosca`;
  `windows-lock-tree.ps1` strips write access from `C:\cosca` with `icacls`. Wiping the
  staging directory first (rather than mirroring the upload straight into `C:\cosca`) keeps a
  file deleted on the host from lingering in the guest after an upload,
  since `file` itself only adds/overwrites, and `/MIR` needs a clean source to mirror from.

Either way this is a **convention, not a security boundary**: the connecting account is an
administrator (Linux: passwordless `sudo`; Windows: `Administrators` membership) and can
always grant itself write access back. It exists so an accidental `cargo test` writing into
its own source tree, or a stray `rm`, doesn't silently succeed.

Cargo builds need a writable output directory, since the synced tree isn't one — `devvm.py
run` sets `CARGO_TARGET_DIR` to a per-guest home directory automatically (`~/cargo-target`
on Linux, `%USERPROFILE%\cargo-target` on Windows), so `devvm.py run linux-x64 -- cargo
test` just works.

## State directories

The state this tool creates per-guest — the QEMU disk overlay, Vagrant's per-guest machine
metadata, the staged tree copy — lives under `.tmp/devvm/<guest>/` in this worktree
(gitignored via the repo's existing `.tmp/` rule). `devvm.py` arranges this by pointing
`VAGRANT_DOTFILE_PATH` at `.tmp/devvm/<guest>/.vagrant` for every `vagrant` invocation it
makes, and `devvm.py destroy` removes it — but only once `vagrant destroy` itself actually
succeeds; if it fails (a stuck lock, a QEMU process it can't reach), `devvm.py` leaves
`.tmp/devvm/<guest>/` in place instead of deleting state out from under a VM that may still
be running, and exits non-zero so the failure isn't silent.

**Not true home-dir isolation, though — Vagrant and vagrant-qemu keep their own state in
`~/.vagrant.d/` regardless, same as any other Vagrant project on the machine, and `devvm.py`
does not redirect or clean any of it:**

- **Box images and plugins** (several GB each): `~/.vagrant.d/{boxes,gems}`. Vagrant ties
  plugin installation and box storage to the same `VAGRANT_HOME`; redirecting it per-project
  would mean reinstalling `vagrant-qemu` (and re-downloading every box) per worktree, which is
  worse than the alternative. Manage this directly with `vagrant box list` / `vagrant box
remove <name>` when you're done with a box.
- **vagrant-qemu's own per-VM runtime files** — a QEMU pid file, its QMP monitor socket, and
  an `options.yml` — under `~/.vagrant.d/tmp/vagrant-qemu/<id>/` while a guest is running.
  `devvm.py destroy`/`vagrant destroy` clean up the VM they belong to; if `destroy` is ever
  skipped, or fails partway (see above), these can be left behind.
- **Vagrant's global machine index**, `~/.vagrant.d/data/machine-index/index` — a manifest of
  every machine Vagrant knows about on this host, across all projects, not per-worktree state.

None of this is huge (unlike the box images), but it means `rm -rf` on this worktree, or even
`devvm.py destroy` for every guest, does not fully return `~/.vagrant.d/` to its pre-devvm
state. If that matters, `vagrant global-status` lists every machine Vagrant's index knows
about, including ones no longer backed by an actual `.tmp/devvm/` directory.

**Disk is usually the constraint, not the tool.** Windows boxes run several GB; check `df -h`
before `up`-ing a Windows guest, and don't keep more than one Windows box downloaded at a
time (`vagrant box list`, then `vagrant box remove` the one you're done with) if space is
tight.

## Forwarded ports are loopback-only, always

Every guest's forwarded ports (WinRM, RDP, SSH) are bound to `127.0.0.1` on the host, never
`0.0.0.0`/every interface — nothing here is meant to be reachable from your LAN. This is
enforced, not just configured: `scripts/devvm/guests/_shared/fix_qemu_loopback_only.rb` is
loaded unconditionally by every guest Vagrantfile and patches
`VagrantPlugins::QEMU::Driver#execute` to rewrite any empty-hostaddr `hostfwd=` clause in the
constructed QEMU command line to loopback before QEMU ever starts — needed because
vagrant-qemu 0.6.3 hardcodes the SSH forward with no `host_ip` seam a Vagrantfile can reach at
all, so `host_ip: "127.0.0.1"` in the Vagrantfile alone doesn't cover SSH.

Because this reaches into a private method by name, it's pinned to exactly vagrant-qemu
`0.6.3` (checked inside the patched `execute` itself, so only starting a new QEMU process
— `vagrant up`/`vagrant reload` when the guest isn't already running — or an `export`/
`package` `qemu-img` call refuses to run against any other installed version; `vagrant
provision` on its own never reaches `Driver#execute` at all, running or not — confirmed by
reading vagrant-qemu's `action.rb`, whose standalone `action_provision` goes straight to the
`Provision` action and never touches `StartInstance` — and `destroy`/`halt` don't either, so
neither can ever leave a running QEMU process unstoppable after a plugin upgrade) and fails
closed with a hard error if a rewritten forward is ever
found still bound to a non-loopback address, rather than silently starting QEMU with a port
exposed to the LAN.

## Known host issue: forwarded-port collisions on some macOS hosts

On at least one Apple Silicon host (confirmed: macOS, Vagrant 2.4.9, both system Ruby 2.6.10
and Vagrant's bundled Ruby 3.3.8), `vagrant up` can fail with `ForwardPortCollision` or
`ForwardPortAutolistEmpty` for a port nothing is actually listening on. Root cause: Vagrant's
own `Vagrant::Util::IsPortOpen.is_port_open?` uses `Socket.tcp(host, port, connect_timeout:
...)`, and that non-blocking-connect code path reports every port as "open" (in use) on this
host regardless of whether anything is bound — reproduced directly against both Rubies, with
both `"0.0.0.0"` and `"127.0.0.1"`, at multiple timeout values; a plain blocking
`TCPSocket.new` against the same ports correctly raises `ECONNREFUSED`. Because the check is
wrong, the auto-correction loop burns through the entire usable port range on the first
collision and has nothing left for the second.

Each guest Vagrantfile works around this by loading
`scripts/devvm/guests/_shared/fix_macos_port_check.rb`, which monkeypatches
`is_port_open?` to use a blocking connect instead, before `vagrant up`'s port-collision
middleware runs. This is loaded unconditionally (harmless on hosts where the bug doesn't
reproduce) rather than gated behind a host check, since the same code path is used by every
provider's forwarded-port handling, not just this tool's guests.
