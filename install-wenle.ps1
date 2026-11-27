#requires -Version 5.1
<#
.SYNOPSIS
  Install a Wenle EDR release package on a clean Windows machine and resume
  after reboot.

.DESCRIPTION
  A release package is a kernel/update package, not a signed one-click
  installer. This script bootstraps it:

    stage 1  validate payload, trust the test certificate, enable test signing,
             install a highest-privilege AtLogOn resume task, reboot
    stage 2  copy the payload, install/start the service, install the driver,
             fetch rules if they are not in the payload, register integrations,
             take the integrity manifest, verify, and start the GUI

  It is idempotent enough to be run again after a failure. The state and log
  live in %ProgramData%\WenleAV, not in the product directory, so they are not
  part of the integrity manifest.

.PARAMETER Resume
  Used by the scheduled resume task. Normal first runs do not need it.

.PARAMETER NoReboot
  Do not reboot automatically. The resume task is still registered.

.PARAMETER DryRun
  Check the payload and machine state, print planned actions, change nothing.

.PARAMETER EnableAmsi
  Register AMSI when av_amsi.dll is present in the payload. It is skipped by
  default because the kernel package may not ship that DLL.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install-wenle.ps1 -DryRun

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\install-wenle.ps1

.NOTES
  The driver is test-signed. A production machine needs a properly signed
  driver, not testsigning. Do not deploy this build to ordinary users.
#>
[CmdletBinding()]
param(
    [switch]$Resume,
    [switch]$NoReboot,
    [switch]$DryRun,
    [switch]$EnableAmsi
)

$ErrorActionPreference = 'Stop'
trap {
    $message = 'installer failed: ' + $_.Exception.Message
    try { Write-Log $message 'ERROR' } catch { Write-Host $message }
    exit 1
}
$InstallDir = 'C:\WenleAV'
$DataDir = Join-Path $env:ProgramData 'WenleAV'
$TaskName = 'WenleInstallResume'
$StatePath = Join-Path $DataDir 'install-state.json'
$LogPath = if ($DryRun) { Join-Path $env:TEMP 'wenle-install-dryrun.log' } else { Join-Path $DataDir 'install.log' }
$ScriptInData = Join-Path $DataDir 'install-wenle.ps1'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Host $line
    try {
        if (-not $DryRun -and -not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {
        # A log failure must not hide the install result.
    }
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Elevated {
    $quoted = '"' + $PSCommandPath + '"'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File ' + $quoted
    if ($Resume) { $arguments += ' -Resume' }
    if ($NoReboot) { $arguments += ' -NoReboot' }
    if ($EnableAmsi) { $arguments += ' -EnableAmsi' }
    Write-Log 'requesting administrator rights'
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $arguments
    exit 0
}

function Test-TestSigning {
    $text = (& bcdedit.exe /enum '{current}' 2>$null | Out-String)
    return ($text -match '(?im)^\s*testsigning\s+Yes\s*$')
}

function Test-SecureBoot {
    try {
        if (Confirm-SecureBootUEFI) { return $true }
    } catch {
        # Legacy BIOS has no Secure Boot variable; that is not an error.
    }
    return $false
}

function Test-HypervisorCodeIntegrity {
    try {
        $guard = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction Stop
        return ($guard.SecurityServicesRunning -contains 2)
    } catch {
        return $false
    }
}

function Install-TestCertificate {
    $certPath = Join-Path $InstallDir 'wenle-test-2026.cer'
    if (-not (Test-Path $certPath)) {
        throw "missing test certificate: $certPath"
    }
    $cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList $certPath
    foreach ($store in @('Root', 'TrustedPublisher')) {
        $location = 'Cert:\LocalMachine\' + $store
        $existing = Get-ChildItem $location | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if (-not $existing) {
            Import-Certificate -FilePath $certPath -CertStoreLocation $location | Out-Null
            Write-Log "trusted test certificate in LocalMachine\$store"
        }
    }
}

function Wait-Service {
    param([string]$Name, [string]$Wanted = 'Running', [int]$Seconds = 30)
    for ($i = 0; $i -lt $Seconds; $i++) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq $Wanted) { return $true }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Test-FilterLoaded {
    try {
        $filters = (& fltmc.exe filters 2>$null | Out-String)
        return ($filters -match '(?im)\bWenleAvFilter\b')
    } catch {
        return $false
    }
}

function Save-State {
    param([hashtable]$State)
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    $State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StatePath -Encoding UTF8
}

function Read-State {
    if (Test-Path $StatePath) {
        $object = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
        $table = @{}
        foreach ($property in $object.PSObject.Properties) {
            $table[$property.Name] = $property.Value
        }
        return $table
    }
    return $null
}

function Register-ResumeTask {
    $scriptPath = $ScriptInData
    if (-not (Test-Path $scriptPath)) {
        $scriptPath = $PSCommandPath
    }
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -Resume'
    if ($EnableAmsi) { $arguments += ' -EnableAmsi' }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $user = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "registered resume task $TaskName (AtLogOn, highest privileges)"
}

function Remove-ResumeTask {
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
        Write-Log "removed resume task $TaskName"
    } catch {
        Write-Log "resume task was not present or could not be removed" 'WARN'
    }
}

function Copy-Payload {
    param([string]$Source)
    $required = @(
        'wenle.exe',
        'wenle-av-service.exe',
        'wenle-gui.exe',
        'wenle-notify.exe',
        'WenleAvFilter.sys',
        'wenle-test-2026.cer',
        'js-policy.json'
    )
    foreach ($name in $required) {
        $from = Join-Path $Source $name
        if (-not (Test-Path $from)) {
            throw "payload is missing $name (expected at $from)"
        }
    }
    if (-not (Test-Path $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
    foreach ($name in $required) {
        $from = Join-Path $Source $name
        $to = Join-Path $InstallDir $name
        if ([IO.Path]::GetFullPath($from) -ne [IO.Path]::GetFullPath($to)) {
            Copy-Item -LiteralPath $from -Destination $to -Force
        }
    }
    foreach ($optional in @('rules.avdb', 'av_amsi.dll')) {
        $from = Join-Path $Source $optional
        $to = Join-Path $InstallDir $optional
        if ((Test-Path $from) -and ([IO.Path]::GetFullPath($from) -ne [IO.Path]::GetFullPath($to))) {
            Copy-Item -LiteralPath $from -Destination $to -Force
            Write-Log "copied optional payload $optional"
        }
    }
    if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }
    if ([IO.Path]::GetFullPath($PSCommandPath) -ne [IO.Path]::GetFullPath($ScriptInData)) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $ScriptInData -Force
    }
    Write-Log "payload copied to $InstallDir"
}

function Show-Status {
    Write-Log '--- Wenle EDR status ---'
    $version = & (Join-Path $InstallDir 'wenle.exe') --version 2>$null | Select-Object -First 1
    Write-Log ("version: " + $version)
    $service = Get-Service -Name WenleAvService -ErrorAction SilentlyContinue
    if ($service) { Write-Log ("service: " + $service.Status) } else { Write-Log 'service: not installed' 'WARN' }
    Write-Log ("filter loaded: " + (Test-FilterLoaded))
    $rules = & (Join-Path $InstallDir 'wenle.exe') rules status 2>$null | Select-Object -First 3
    if ($rules) { Write-Log ("rules: " + ($rules -join ' | ')) }
    $verify = & (Join-Path $InstallDir 'wenle.exe') protect verify 2>$null | Select-Object -Last 1
    if ($verify) { Write-Log ("integrity: " + $verify) }
}

function Complete-Install {
    param([hashtable]$State)
    $State.stage = 'complete'
    $State.completed_at = (Get-Date).ToString('o')
    Save-State $State
    Remove-ResumeTask
    Show-Status
    Start-Process -FilePath (Join-Path $InstallDir 'wenle-gui.exe') -WorkingDirectory $InstallDir -ErrorAction SilentlyContinue
    Start-Process -FilePath (Join-Path $InstallDir 'wenle-notify.exe') -WorkingDirectory $InstallDir -ErrorAction SilentlyContinue
    Write-Log 'installation complete'
}

function Invoke-Install {
    param([hashtable]$State)

    if (-not (Test-TestSigning)) {
        throw 'testsigning is not enabled after reboot; Secure Boot or policy is preventing it. Disable Secure Boot, run "bcdedit /set testsigning on", reboot, then run this script with -Resume.'
    }
    Install-TestCertificate

    if (-not (Test-FilterLoaded)) {
        $service = Get-Service -Name WenleAvService -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log 'installing the service'
            & (Join-Path $InstallDir 'wenle.exe') service install
            & (Join-Path $InstallDir 'wenle.exe') service start
            if (-not (Wait-Service -Name 'WenleAvService' -Wanted 'Running' -Seconds 30)) {
                throw 'WenleAvService did not reach Running'
            }
        } else {
            Write-Log ("existing service: " + $service.Status)
            if ($service.Status -ne 'Running') {
                & (Join-Path $InstallDir 'wenle.exe') service start
                if (-not (Wait-Service -Name 'WenleAvService' -Wanted 'Running' -Seconds 30)) {
                    throw 'existing WenleAvService did not reach Running'
                }
            }
        }

        $driver = Get-Service -Name WenleAvFilter -ErrorAction SilentlyContinue
        if (-not $driver) {
            Write-Log 'installing the kernel driver'
            & (Join-Path $InstallDir 'wenle.exe') integrate driver install
        }
    }

    $ruleDb = Join-Path $DataDir 'db\rules.avdb'
    if (-not (Test-Path $ruleDb)) {
        $payloadRules = Join-Path $InstallDir 'rules.avdb'
        if (Test-Path $payloadRules) {
            New-Item -ItemType Directory -Path (Split-Path $ruleDb) -Force | Out-Null
            Copy-Item -LiteralPath $payloadRules -Destination $ruleDb -Force
            Write-Log 'installed rules.avdb from payload'
        } else {
            Write-Log 'rules.avdb is not in the payload; downloading YARA-Forge rules'
            try {
                & (Join-Path $InstallDir 'wenle.exe') rules update
                if ($LASTEXITCODE -ne 0) { Write-Log 'rules update returned a non-zero exit code' 'WARN' }
            } catch {
                Write-Log ("rules update failed: " + $_.Exception.Message) 'WARN'
            }
        }
    }

    foreach ($command in @('shell', 'startup', 'notifications')) {
        try {
            & (Join-Path $InstallDir 'wenle.exe') integrate $command install
            Write-Log "integrated $command"
        } catch {
            Write-Log ("integration $command failed: " + $_.Exception.Message) 'WARN'
        }
    }
    $amsiDll = Join-Path $InstallDir 'av_amsi.dll'
    if ($EnableAmsi -and (Test-Path $amsiDll)) {
        try {
            & (Join-Path $InstallDir 'wenle.exe') integrate amsi install
            Write-Log 'integrated AMSI'
        } catch {
            Write-Log ("AMSI integration failed: " + $_.Exception.Message) 'WARN'
        }
    } elseif ($EnableAmsi) {
        Write-Log 'AMSI requested, but av_amsi.dll is not in the payload; skipped' 'WARN'
    }

    if (-not (Test-FilterLoaded)) {
        if ($State.attempts -ge 2) {
            throw 'driver is still not loaded after two reboots; check testsigning, Secure Boot, HVCI and sc query WenleAvFilter'
        }
        $State.stage = 'awaiting_driver'
        $State.attempts = [int]$State.attempts + 1
        Save-State $State
        Register-ResumeTask
        Write-Log 'driver installed but not loaded; a reboot is required'
        if ($NoReboot) { return }
        Restart-Computer -Force
        return
    }

    try {
        & (Join-Path $InstallDir 'wenle.exe') protect manifest | Out-Null
        Write-Log 'recorded integrity manifest'
    } catch {
        Write-Log ("protect manifest failed: " + $_.Exception.Message) 'WARN'
    }

    Complete-Install $State
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if (-not $DryRun -and -not (Test-Path $DataDir)) {
    try { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null } catch {}
}

if ($DryRun) {
    $source = $PSScriptRoot
    $required = @('wenle.exe', 'wenle-av-service.exe', 'wenle-gui.exe', 'wenle-notify.exe',
                  'WenleAvFilter.sys', 'wenle-test-2026.cer', 'js-policy.json')
    foreach ($name in $required) {
        if (Test-Path (Join-Path $source $name)) {
            Write-Log "dry-run: found $name"
        } else {
            Write-Log "dry-run: MISSING $name" 'WARN'
        }
    }
    Write-Log ("dry-run: admin=" + (Test-Admin))
    Write-Log ("dry-run: testsigning=" + (Test-TestSigning))
    Write-Log ("dry-run: secureboot=" + (Test-SecureBoot))
    Write-Log ("dry-run: hvci=" + (Test-HypervisorCodeIntegrity))
    Write-Log ("dry-run: service exists=" + [bool](Get-Service -Name WenleAvService -ErrorAction SilentlyContinue))
    Write-Log ("dry-run: filter loaded=" + (Test-FilterLoaded))
    Write-Log 'dry-run: no changes made'
    exit 0
}

if (-not (Test-Admin)) {
    Invoke-Elevated
}

Write-Log '--- Wenle EDR installer ---'
$state = Read-State
if ($Resume -and $state -and $state.stage -eq 'complete') {
    Write-Log 'state says the installation is already complete'
    Show-Status
    Remove-ResumeTask
    exit 0
}

if (-not $Resume) {
    if (Test-SecureBoot) {
        throw 'Secure Boot is on. This test-signed driver cannot be installed while Secure Boot is on. Disable it in firmware, then run the script again.'
    }
    if (Test-HypervisorCodeIntegrity) {
        Write-Log 'HVCI is on; a test-signed driver may be refused. Disable Memory Integrity if the driver does not load.' 'WARN'
    }
    $source = $PSScriptRoot
    Copy-Payload -Source $source
    if (-not (Test-TestSigning)) {
        Write-Log 'enabling testsigning'
        & bcdedit.exe /set testsigning on | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'bcdedit could not enable testsigning; check Secure Boot and firmware policy'
        }
        $hash = @{ stage = 'awaiting_boot'; attempts = 0; started_at = (Get-Date).ToString('o') }
        Save-State $hash
        Register-ResumeTask
        Write-Log 'reboot required to activate testsigning'
        if ($NoReboot) { Write-Log 'NoReboot set; reboot manually to resume'; exit 0 }
        Restart-Computer -Force
        exit 0
    }
    $hash = @{ stage = 'installing'; attempts = 0; started_at = (Get-Date).ToString('o') }
    Save-State $hash
    Invoke-Install $hash
    exit 0
}

# Resume path after a reboot.
if (-not $state) {
    $state = @{ stage = 'installing'; attempts = 0; started_at = (Get-Date).ToString('o') }
}
if ($state.stage -eq 'awaiting_boot') {
    $state.stage = 'installing'
    Save-State $state
}
Invoke-Install $state
