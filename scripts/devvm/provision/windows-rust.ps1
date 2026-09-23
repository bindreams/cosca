# Installs a Rust toolchain (via rustup-init) and cargo-nextest for the `vagrant` user, so
# `devvm.py run windows-x64 -- cargo nextest run ...` has something to run. Idempotent: each
# step skips itself if already done.
#
# GNU host triplet, not MSVC: a vanilla Windows box has no Visual Studio linker, and
# rustup's GNU toolchain bundles its own (mingw-w64) linker via a rustup component, so no
# multi-gigabyte Build Tools download is needed just to get a working `cargo build`. cosca's
# own Windows-specific code (Job Objects, elevation, WinRM-adjacent APIs) links against the
# same Win32 import libraries either way - the GNU/MSVC choice is a toolchain/ABI detail, not
# a capability restriction.

$ErrorActionPreference = "Stop"

# rustup-init.exe and cargo-nextest are run in ways that keep their output off this script's
# own real stderr handle. This isn't cosmetic - it's required for `devvm.py up`/`sync
# windows-x64` to succeed at all, for a subtle reason specific to how Vagrant's shell
# provisioner runs this script:
#
# Vagrant routes this script through WinRM's PSRP-based PowerShell shell (`lib/winrm/shells/
# power_shell.rb` in the `winrm` gem - confirmed by reading vagrant 2.4.9's vendored copy
# directly, 2026-09-23), which appends this trailer to whatever command it sends:
#
#   if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }
#
# That trailer runs in the OUTER session, once, after our *entire* `powershell -file
# windows-rust.ps1` invocation completes, and checks that invocation's own `$?` - not
# `$LASTEXITCODE` alone. Windows PowerShell 5.1 sets `$?` to `$false` for a native command
# whenever anything reaches that command's real stderr stream, regardless of exit code. Since
# `$LASTEXITCODE` is 0 (falsy in PowerShell's `if()`), `!$?` alone is enough to hit the
# trailer's `else { exit 1 }` branch - an explicit `exit 0` at the end of this script does
# NOT help (measured directly, 2026-09-23: the script's own process exit code was
# independently confirmed 0 via a direct `vagrant winrm -c` invocation of the identical
# command line - which doesn't route through this PSRP trailer - while `devvm.py up` still
# failed).
#
# rustup-init.exe writes benign "info: ..." progress lines to stderr, and with nothing
# redirecting that, it passes straight through to this script's own process - which is
# itself a native command from the outer session's point of view - tripping the trailer.
#
# Two narrower fixes were tried and measured directly (2026-09-23) before landing on
# `Start-Process`:
#   1. Wrapping the whole script in a function and writing its merged output (`*>&1`) through
#      `Write-Host`. This made things worse: piping a function's `*>&1` output through a
#      downstream cmdlet, under `$ErrorActionPreference = "Stop"`, escalates a native
#      command's stderr into an immediate *terminating* error instead of the non-terminating
#      "displayed but continues" behavior PowerShell otherwise gives it - the script aborted
#      at the very first rustup-init line, before any of its own output.
#   2. Redirecting stderr at the call site with `2>$null` (e.g. `& $rustupInit ... 2>$null`).
#      This suppressed every stderr line EXCEPT THE FIRST: PowerShell has a known quirk where
#      a native command's very first stderr line can bypass `2>` redirection entirely (it's
#      read and formatted as a `NativeCommandError` before the redirect target takes effect),
#      so `devvm.py up` still failed on that one line.
# `Start-Process ... -Wait -PassThru` sidesteps both: it launches rustup-init as a genuinely
# separate process rather than an inline pipeline invocation, so none of its stdio interacts
# with this script's own PowerShell stream/error machinery at all - proven by the VC++
# redistributable install below, which has used this pattern from the start and has never
# shown this problem across every test run so far. Actual failures are still caught: every
# native call below has its own explicit exit-code/output check immediately after it, which
# `throw`s on failure.

# rustup-init doesn't update the CURRENT process's PATH after installing - re-derive cargo's
# bin dir directly (matches rustup's own default: %USERPROFILE%\.cargo\bin) so the
# already-installed-version check further down in THIS script (`Get-Command cargo-nextest`,
# and `cargo nextest --version`) sees the freshly-installed toolchain immediately, rather than
# relying on a fresh process to pick up the user PATH change rustup persists to the registry.
# (This script never runs `cargo install cargo-nextest` - nextest is installed below by
# downloading and expanding a prebuilt release zip, not compiled via cargo.)
$cargoBin = "$env:USERPROFILE\.cargo\bin"
$env:PATH = "$cargoBin;$env:PATH"

if (Get-Command cargo -ErrorAction SilentlyContinue) {
    Write-Host "devvm: cargo already present ($(cargo --version 2>$null)), skipping rustup install"
} else {
    $rustupInit = "$env:TEMP\rustup-init.exe"
    Invoke-WebRequest -Uri "https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-gnu/rustup-init.exe" -OutFile $rustupInit
    $rustupProcess = Start-Process -FilePath $rustupInit -ArgumentList @(
        "-y", "--profile", "minimal",
        "--default-toolchain", "stable-x86_64-pc-windows-gnu",
        "--default-host", "x86_64-pc-windows-gnu"
    ) -Wait -PassThru
    if ($rustupProcess.ExitCode -ne 0) {
        throw "devvm: rustup-init failed (exit $($rustupProcess.ExitCode))"
    }
    Remove-Item -Path $rustupInit -ErrorAction SilentlyContinue
    Write-Host "devvm: installed $(& "$cargoBin\cargo.exe" --version 2>$null)"
}

# cargo-nextest's Windows release is an MSVC-target binary - it needs the Microsoft Visual
# C++ Redistributable's runtime DLLs (vcruntime140.dll etc.), even though the GNU-triplet
# Rust toolchain installed above doesn't need them itself. Measured directly (2026-09-23):
# without this, invoking cargo-nextest.exe at all - even --version - fails immediately with
# exit code -1073741515 (0xC0000135, STATUS_DLL_NOT_FOUND) and no stdout/stderr, which the
# nextest-install block below (before this fix) silently swallowed into an empty version
# string instead of catching. nextest-rs publishes no windows-gnu build (checked the
# cargo-nextest-0.9.137 release asset list - only *-pc-windows-msvc for both x86_64 and
# aarch64), so switching targets isn't an option; the redistributable has to be installed.
# This runs BEFORE the "is cargo-nextest already installed?" check below, since that check
# itself invokes cargo-nextest.exe.
#
# HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64's Installed=1 is Microsoft's own
# documented detection key for an already-installed VC++ 2015-2022 x64 redistributable
# (https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files).
$vcRuntimeKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64"
$vcRuntimeInstalled = (Test-Path $vcRuntimeKey) -and
    ((Get-ItemProperty -Path $vcRuntimeKey -Name Installed -ErrorAction SilentlyContinue).Installed -eq 1)
if ($vcRuntimeInstalled) {
    Write-Host "devvm: VC++ redistributable already present, skipping"
} else {
    $vcRedistExe = "$env:TEMP\vc_redist.x64.exe"
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $vcRedistExe
    $vcProcess = Start-Process -FilePath $vcRedistExe -ArgumentList "/install", "/quiet", "/norestart" -Wait -PassThru
    Remove-Item -Path $vcRedistExe -ErrorAction SilentlyContinue
    # Measured directly (2026-09-23): a first-time install on a guest that never had any VC++
    # redistributable completes with exit 0, no reboot needed. 3010 (success, reboot
    # required) is a real MSI outcome in general - e.g. upgrading a version whose DLLs a
    # running process already has loaded - but not one this fresh-guest path hit; if it ever
    # does happen, failing loudly here is correct: silently treating 3010 as "good enough"
    # would ship a cargo-nextest.exe that keeps failing until a reboot nothing else in this
    # script triggers.
    if ($vcProcess.ExitCode -ne 0) {
        throw "devvm: vc_redist.x64.exe install failed (exit $($vcProcess.ExitCode))"
    }
    Write-Host "devvm: installed VC++ redistributable"
}

# This version matches the planned CI pin for cargo-nextest (the Skuld migration, #151) - not
# a pin that exists in CI today. Installing the same version here means `devvm.py run
# windows-x64 -- cargo nextest run ...` matches what CI is planned to run instead of whatever
# a fresh install would resolve to today.
#
# Downloads nextest's own prebuilt release binary rather than `cargo install
# cargo-nextest --locked` (compiling it from source). Measured directly (2026-09-23):
# compiling cargo-nextest from source under this box's TCG (cross-arch emulation on Apple
# Silicon) ran for over an hour without finishing - not hung (CPU pegged the whole time,
# confirmed via the host's `ps`/`lsof`), just genuinely too slow to be workable for a
# throwaway VM that gets destroyed and recreated often. The prebuilt .exe is a standalone
# binary - it runs fine regardless of the local toolchain being the GNU host triplet above,
# since nextest only shells out to `cargo build` and then runs the resulting test binaries
# directly; it doesn't need to have been built with the same toolchain itself.
$nextestVersion = "0.9.137"
# SHA-256 of the exact release asset, fetched and independently verified (both against
# nextest's own published `.sha256` files and a fresh `Get-FileHash` of a freshly downloaded
# copy) 2026-09-23. Checked before extracting (below) so a corrupted or tampered download is a
# hard failure, never silently `Expand-Archive`'d.
$nextestSha256 = "88c746b41b1e96165028ef90b9dac5d37eb923e4e00aee6b9080a038f1ac2705"
$installedVersion = if (Get-Command cargo-nextest -ErrorAction SilentlyContinue) {
    ((cargo nextest --version 2>$null) -split " ")[1]
} else {
    $null
}

if ($installedVersion -eq $nextestVersion) {
    Write-Host "devvm: cargo-nextest $nextestVersion already present, skipping"
} else {
    $nextestZip = "$env:TEMP\cargo-nextest-$nextestVersion.zip"
    $nextestUrl = "https://github.com/nextest-rs/nextest/releases/download/cargo-nextest-$nextestVersion/cargo-nextest-$nextestVersion-x86_64-pc-windows-msvc.zip"
    Invoke-WebRequest -Uri $nextestUrl -OutFile $nextestZip
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -Path $nextestZip).Hash
    if ($actualSha256 -ine $nextestSha256) {
        Remove-Item -Path $nextestZip -ErrorAction SilentlyContinue
        throw "devvm: cargo-nextest download checksum mismatch: expected $nextestSha256, got $actualSha256"
    }
    New-Item -ItemType Directory -Path $cargoBin -Force | Out-Null
    # -Force overwrites cargo-nextest.exe in place if a different (e.g. mismatched) version
    # was left there by an interrupted previous run.
    Expand-Archive -Path $nextestZip -DestinationPath $cargoBin -Force
    Remove-Item -Path $nextestZip -ErrorAction SilentlyContinue
    $installedVersionAfter = ((cargo nextest --version 2>$null) -split " ")[1]
    if ($installedVersionAfter -ne $nextestVersion) {
        # `cargo nextest --version` failing (e.g. a missing DLL, or a corrupt download) exits
        # non-zero with no output rather than throwing a catchable PowerShell error - measured
        # directly (2026-09-23) via the STATUS_DLL_NOT_FOUND case above, before the VC++ step
        # was added. Without this check that failure mode silently produces a blank "devvm:
        # installed cargo-nextest " line instead of catching the broken install.
        throw "devvm: cargo-nextest install verification failed - expected version $nextestVersion, got '$installedVersionAfter'"
    }
    Write-Host "devvm: installed cargo-nextest $installedVersionAfter"
}

exit 0
