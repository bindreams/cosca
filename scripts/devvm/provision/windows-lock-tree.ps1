# Strips write access from the uploaded working-tree copy (see windows-mirror-tree.ps1,
# which devvm.py's provision_windows_guest runs directly over `vagrant winrm` just before
# this - not a Vagrantfile-declared provisioner; see that Vagrantfile's own comment on why -
# and mirrors the WinRM-uploaded staging copy into this path). Best-effort footgun
# prevention, matching the rsync --chmod=F444 used for the Linux guests - not a security
# boundary: the connecting account is itself an Administrator and can always re-grant itself
# access, same as root can on the Linux guests.

$ErrorActionPreference = "Stop"
$path = "C:\cosca"

if (Test-Path $path) {
    # Everyone: read + execute only. Administrators: full control, so a later `devvm.py sync`
    # (which re-runs this same upload) can still overwrite the tree.
    #
    # Two steps, in this order - NOT one `/grant:r ... /T` call. Measured directly
    # (2026-09-23): applying `/grant:r "*SID:(OI)(CI)perm"` with /T grants correctly on
    # directories but silently produces an EMPTY DACL (deny-all) on files several levels
    # deep (e.g. everything under scripts/), even though icacls reports
    # "Successfully processed ... Failed processing 0 files" - confirmed reproducible against
    # both C:\cosca and a throwaway tree with no relation to this repo, so it's a real icacls
    # behavior on this box, not a staging/sync bug. (OI)(CI) are container-inheritance flags;
    # applying them directly to a leaf file via /grant:r appears to be what triggers it.
    #
    # The fix: unprotect every existing descendant first (`/inheritance:e /T` - safe no-op if
    # nothing is protected yet, e.g. brand-new files), THEN set the explicit inheritable grant
    # on $path alone (no /T). NTFS's own ACE-propagation machinery then pushes that grant down
    # to every non-protected descendant - director[y|ies] and files alike - producing correct,
    # non-empty, inherited ACEs on all of them. Verified directly: files under a nested
    # subdirectory get a correct inherited (Everyone RX, Administrators FA) ACE this way, where
    # the single `/grant:r ... /T` call left them with zero ACEs.
    icacls $path /inheritance:e /T /Q
    if ($LASTEXITCODE -ne 0) {
        throw "devvm: icacls failed to unprotect descendants of $path before re-locking it (exit $LASTEXITCODE)"
    }
    icacls $path /inheritance:r /grant:r "*S-1-1-0:(OI)(CI)RX" "*S-1-5-32-544:(OI)(CI)F" /Q
    if ($LASTEXITCODE -ne 0) {
        throw "devvm: icacls failed to lock down $path (exit $LASTEXITCODE)"
    }
}
