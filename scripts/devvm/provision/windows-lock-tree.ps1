# Strips write access from the uploaded working-tree copy (see the "file" provisioner in
# scripts/devvm/guests/windows-x64/Vagrantfile that runs just before this). Best-effort
# footgun prevention, matching the rsync --chmod=F444 used for the Linux guests - not a
# security boundary: the connecting account is itself an Administrator and can always
# re-grant itself access, same as root can on the Linux guests.

$ErrorActionPreference = "Stop"
$path = "C:\cosca"

if (Test-Path $path) {
    # Everyone: read + execute only. Administrators: full control, so a later `devvm.py sync`
    # (which re-runs this same upload) can still overwrite the tree.
    icacls $path /inheritance:r /grant:r "*S-1-1-0:(OI)(CI)RX" "*S-1-5-32-544:(OI)(CI)F" /T /Q
    if ($LASTEXITCODE -ne 0) {
        throw "devvm: icacls failed to lock down $path (exit $LASTEXITCODE)"
    }
}
