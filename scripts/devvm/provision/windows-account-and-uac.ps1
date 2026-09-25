# Ensures the devvm Windows guest exposes UAC in its default, interactive-consent state,
# that the account this tool connects as is an ordinary Administrators member — not the
# built-in RID-500 Administrator, which Windows elevates silently, without a UAC prompt,
# regardless of EnableLUA — and that the account autologs in at boot so a real interactive
# (session 1) logon exists for windows-run-unelevated.ps1's Register-ScheduledTask
# (-LogonType Interactive) probe runner to borrow. Idempotent: safe to re-run any time this
# script runs, which is every `up`/`sync` — it's driven directly over `vagrant winrm` by
# run_windows_script (scripts/devvm.py), not Vagrant's shell provisioner.
#
# ConsentPromptBehaviorAdmin is only flipped away from the interactive default (5) when
# DEVVM_WINDOWS_AUTO_CONSENT=1 is set — see scripts/devvm.py's --allow-elevation flag and
# scripts/README.md#windows-guests. Never flipped silently. It's read live by AppInfo at
# elevation-request time, so no reboot is needed for it to take effect.
#
# EnableLUA and autologon, by contrast, only take effect for a session's split/filtered token
# at the NEXT LOGON — changing them live does nothing for an already-running session. This
# script only detects and applies changes (never blindly reboots on every run) and reports
# whether one is needed via a DEVVM_REBOOT_REQUIRED marker on its last output line;
# provision_windows_guest (scripts/devvm.py) scans for that marker and, if set, calls
# reboot_windows_guest_and_wait to actually reboot (issued directly, not via Vagrant's
# reboot-if-needed/wait_for_reboot capability — see the Vagrantfile's provisioning comment for
# why). It does NOT re-run this script afterward to re-verify the settings — the write above
# already happened. Confirming a real interactive session exists on top of the reboot is a
# separate concern: provision_windows_guest calls wait_for_windows_session for that,
# conditionally — only when get_windows_autologon_configured says autologon is set — once, at
# the end of its own flow — not something reboot_windows_guest_and_wait itself does.

$ErrorActionPreference = "Stop"
$policyKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Must match config.winrm.username / config.winrm.password in windows-x64/Vagrantfile — this
# box's credentials are already fixed, non-secret values ("vagrant"/"vagrant"), not something
# worth threading through another layer of parameters.
$autoLogonUser = "vagrant"
$autoLogonPassword = "vagrant"

$rebootNeeded = $false

# 1. UAC itself stays on. Some eval/vanilla box images ship with it toggled off; force it
#    back to the Windows default so `runas` from an unelevated process actually goes through
#    Admin Approval Mode — the behaviour this VM exists to measure. Only reboot if this is
#    actually changing something.
$currentLua = (Get-ItemProperty -Path $policyKey -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
if ($currentLua -ne 1) {
    Set-ItemProperty -Path $policyKey -Name "EnableLUA" -Value 1 -Type DWord
    $rebootNeeded = $true
    Write-Host "devvm: EnableLUA was '$currentLua', set to 1 - this needs a reboot before it's live for a fresh interactive logon's filtered token."
}

# 2. Confirm the connecting account isn't the built-in Administrator (SID ...-500). Bento's
#    Windows boxes provision a "vagrant" local-admin account distinct from the built-in
#    Administrator; fail loudly instead of silently testing the wrong account if that ever
#    changes upstream.
$account = Get-LocalUser -Name $env:USERNAME -ErrorAction SilentlyContinue
if ($null -eq $account) {
    throw "devvm: could not resolve local account '$($env:USERNAME)' - cannot verify it isn't the built-in Administrator"
}
if ($account.SID.Value.EndsWith("-500")) {
    throw "devvm: the account this tool connects as ('$($env:USERNAME)') is the built-in Administrator (RID 500), which Windows elevates without a UAC prompt. This box no longer matches the 'ordinary admin, UAC on' guest this tool promises - update scripts/devvm/guests/windows-x64/Vagrantfile to connect as a non-built-in admin account."
}
$members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$isAdmin = @($members | Where-Object { $_.Name -like "*\$($env:USERNAME)" -or $_.Name -eq $env:USERNAME }).Count -gt 0
if (-not $isAdmin) {
    throw "devvm: account '$($env:USERNAME)' is not a member of Administrators"
}

# 3. The opt-in toggle: auto-approve consent (no secure-desktop prompt) for unattended probe
#    runs. Off (Windows default: prompt) unless the developer explicitly asked for it. Read
#    live by AppInfo, so no reboot needed here.
$autoConsent = $env:DEVVM_WINDOWS_AUTO_CONSENT -eq "1"
$consentValue = if ($autoConsent) { 0 } else { 5 }
Set-ItemProperty -Path $policyKey -Name "ConsentPromptBehaviorAdmin" -Value $consentValue -Type DWord

if ($autoConsent) {
    Write-Host "devvm: UAC consent auto-approve is ON (ConsentPromptBehaviorAdmin=0) - opt-in probe mode."
} else {
    Write-Host "devvm: UAC consent prompts are ON (ConsentPromptBehaviorAdmin=5) - Windows default."
}

# 4. Autologon: the whole point of this guest is measuring the UNELEVATED interactive-session
#    UAC path (see windows-run-unelevated.ps1) - that needs an actual active console (session
#    1) logon for its Register-ScheduledTask (-LogonType Interactive) probe runner to borrow a
#    filtered token from, and a headless VM has no console session unless something logs in.
#    AutoAdminLogon establishes that at every boot.
#    Also only takes effect at the next boot; only reboot if actually changing something.
$currentAutoAdminLogon = (Get-ItemProperty -Path $winlogonKey -Name "AutoAdminLogon" -ErrorAction SilentlyContinue).AutoAdminLogon
$currentDefaultUserName = (Get-ItemProperty -Path $winlogonKey -Name "DefaultUserName" -ErrorAction SilentlyContinue).DefaultUserName
$currentDefaultPassword = (Get-ItemProperty -Path $winlogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue).DefaultPassword
$currentDefaultDomainName = (Get-ItemProperty -Path $winlogonKey -Name "DefaultDomainName" -ErrorAction SilentlyContinue).DefaultDomainName
$autologonNeedsChange = (
    $currentAutoAdminLogon -ne "1" -or
    $currentDefaultUserName -ne $autoLogonUser -or
    $currentDefaultPassword -ne $autoLogonPassword -or
    $currentDefaultDomainName -ne "."
)
if ($autologonNeedsChange) {
    Set-ItemProperty -Path $winlogonKey -Name "AutoAdminLogon" -Value "1" -Type String
    Set-ItemProperty -Path $winlogonKey -Name "DefaultUserName" -Value $autoLogonUser -Type String
    Set-ItemProperty -Path $winlogonKey -Name "DefaultPassword" -Value $autoLogonPassword -Type String
    Set-ItemProperty -Path $winlogonKey -Name "DefaultDomainName" -Value "." -Type String
    $rebootNeeded = $true
    Write-Host "devvm: autologon for '$autoLogonUser' was not set (or stale), configured - this needs a reboot before a console session actually exists."
}

# Last line, always: devvm.py's provision_windows_guest scans this script's combined
# stdout/stderr for this exact marker (REBOOT_MARKER_TRUE/REBOOT_MARKER_FALSE).
if ($rebootNeeded) {
    Write-Host "DEVVM_REBOOT_REQUIRED=1"
} else {
    Write-Host "DEVVM_REBOOT_REQUIRED=0"
}
