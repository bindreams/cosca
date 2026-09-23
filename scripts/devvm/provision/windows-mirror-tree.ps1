# Mirrors the freshly-uploaded staging copy into C:\cosca, including deletions.
#
# Runs after the "file" provisioner uploads devvm.py's staged tree to C:\cosca-stage (itself
# wiped just before that upload by windows-clean-stage.ps1, so the staging copy is always an
# exact match for the host tree) and before windows-lock-tree.ps1 locks C:\cosca down.
# robocopy /MIR makes C:\cosca an exact mirror of the staging copy, deleting anything in
# C:\cosca that's no longer present upstream — the WinRM upload step alone cannot do this.

$ErrorActionPreference = "Stop"
$source = "C:\cosca-stage"
$dest = "C:\cosca"

New-Item -ItemType Directory -Path $dest -Force | Out-Null

# robocopy's exit codes are a bitmask, not the usual 0-success convention: 0-7 are all
# "succeeded, here's what happened" (0 = nothing to copy, 1 = files copied, 2 = extra files
# removed, etc. - see Microsoft's robocopy exit code docs); 8 or above means at least one
# real failure.
robocopy $source $dest /MIR /R:2 /W:1 /NFL /NDL /NJH /NJS
$robocopyExit = $LASTEXITCODE
if ($robocopyExit -ge 8) {
    throw "devvm: robocopy failed mirroring $source to $dest (exit $robocopyExit)"
}
