# Raises the WinRM per-shell memory quota. Every `vagrant winrm` command, and so every
# `devvm.py run`, runs in a shell whose whole process tree shares that quota, and the
# gusztavvargadr/windows-11 box ships 800 MB: rustup-init aborts there with "memory allocation of
# 16777216 bytes failed" (exit -1073740791) and a cargo build would hit the same wall. Applies to
# shells created after this one, so it has to run before windows-rust.ps1 in its own command.

$ErrorActionPreference = "Stop"
$quotaMB = 4096

if ([int](Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value -lt $quotaMB) {
    Set-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB $quotaMB
    Write-Host "devvm: raised the WinRM per-shell memory quota to $quotaMB MB"
}
