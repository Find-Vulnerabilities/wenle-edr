#requires -RunAsAdministrator
<#
.SYNOPSIS
  Benign persistence probes for testing Wenle's autostart protection.

.DESCRIPTION
  Every payload is a harmless cmd.exe line that appends a marker to
  C:\WenleTest\triggered.log. Nothing encrypts, deletes or downloads.
  Each probe installs one autostart mechanism, checks whether the value is
  still present, then removes it again. Run only in a disposable VM.

  This is a test harness, not malware. The point is to make the write and
  the resulting value visible to the product's behaviour engine so a gap in
  detection or rollback can be measured.
#>

$ErrorActionPreference = 'Continue'
$base = 'C:\WenleTest'
$log = Join-Path $base 'probes.log'
$marker = Join-Path $base 'marker.cmd'
$triggered = Join-Path $base 'triggered.log'
New-Item -ItemType Directory -Path $base -Force | Out-Null
@'
@echo off
echo triggered %DATE% %TIME% %* >> C:\WenleTest\triggered.log
'@ | Set-Content -LiteralPath $marker -Encoding ASCII
$payload = ('cmd.exe /c "{0}" {1}' -f $marker, '%NAME%')

function Say([string]$text) {
    $line = ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $text)
    Add-Content -LiteralPath $log -Value $line -Encoding UTF8
}

function Probe {
    param(
        [string]$Name,
        [scriptblock]$Install,
        [scriptblock]$Present,
        [scriptblock]$Cleanup
    )
    Say ("BEGIN {0}" -f $Name)
    try {
        & $Install
        Start-Sleep -Seconds 5
        $seen = $false
        try { $seen = [bool](& $Present) } catch { Say ("check error: {0}" -f $_.Exception.Message) }
        Say ("{0}: present={1}" -f $Name, $seen)
    } catch {
        Say ("{0}: install error: {1}" -f $Name, $_.Exception.Message)
    } finally {
        try { & $Cleanup } catch { Say ("{0}: cleanup error: {1}" -f $Name, $_.Exception.Message) }
        Say ("END {0}" -f $Name)
    }
}

# ---------------------------------------------------------------- registry
$runUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$runMachine = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
$runOnceUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$runOnceMachine = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
$policyUser = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
$policyMachine = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'

Probe 'HKCU Run' {
    New-Item -Path $runUser -Force | Out-Null
    New-ItemProperty -Path $runUser -Name 'WenleProbeRun' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $runUser -Name 'WenleProbeRun' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $runUser -Name 'WenleProbeRun' -Force -ErrorAction SilentlyContinue
}

Probe 'HKLM Run' {
    New-Item -Path $runMachine -Force | Out-Null
    New-ItemProperty -Path $runMachine -Name 'WenleProbeRun' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $runMachine -Name 'WenleProbeRun' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $runMachine -Name 'WenleProbeRun' -Force -ErrorAction SilentlyContinue
}

Probe 'HKCU RunOnce' {
    New-Item -Path $runOnceUser -Force | Out-Null
    New-ItemProperty -Path $runOnceUser -Name 'WenleProbeOnce' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $runOnceUser -Name 'WenleProbeOnce' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $runOnceUser -Name 'WenleProbeOnce' -Force -ErrorAction SilentlyContinue
}

Probe 'HKLM RunOnce' {
    New-Item -Path $runOnceMachine -Force | Out-Null
    New-ItemProperty -Path $runOnceMachine -Name 'WenleProbeOnce' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $runOnceMachine -Name 'WenleProbeOnce' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $runOnceMachine -Name 'WenleProbeOnce' -Force -ErrorAction SilentlyContinue
}

Probe 'HKCU policy Run' {
    New-Item -Path $policyUser -Force | Out-Null
    New-ItemProperty -Path $policyUser -Name 'WenleProbePolicy' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $policyUser -Name 'WenleProbePolicy' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $policyUser -Name 'WenleProbePolicy' -Force -ErrorAction SilentlyContinue
}

Probe 'HKLM policy Run' {
    New-Item -Path $policyMachine -Force | Out-Null
    New-ItemProperty -Path $policyMachine -Name 'WenleProbePolicy' -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $policyMachine -Name 'WenleProbePolicy' -ErrorAction SilentlyContinue) -ne $null } {
    Remove-ItemProperty -Path $policyMachine -Name 'WenleProbePolicy' -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- startup folder
$startup = [Environment]::GetFolderPath('Startup')
$startupFile = Join-Path $startup 'WenleProbe.cmd'
Probe 'Startup folder' {
    Copy-Item -LiteralPath $marker -Destination $startupFile -Force
} { Test-Path -LiteralPath $startupFile } {
    Remove-Item -LiteralPath $startupFile -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- scheduled task
Probe 'Scheduled task ONLOGON' {
    & schtasks.exe /Create /TN 'WenleProbeTask' /SC ONLOGON /TR ('"{0}" task' -f $marker) /RL HIGHEST /F *> $null
} { (& schtasks.exe /Query /TN 'WenleProbeTask' 2>&1) -match 'WenleProbeTask' } {
    & schtasks.exe /Delete /TN 'WenleProbeTask' /F *> $null
}

# ---------------------------------------------------------------- service
Probe 'Service image path' {
    & sc.exe create WenleProbeSvc binPath= ('cmd.exe /c "{0}" service' -f $marker) start= demand *> $null
} { (& sc.exe qc WenleProbeSvc 2>&1) -match 'WenleProbeSvc' } {
    & sc.exe delete WenleProbeSvc *> $null
}

# ---------------------------------------------------------------- winlogon
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$shell = (Get-ItemProperty -Path $winlogon -Name Shell -ErrorAction SilentlyContinue).Shell
$userinit = (Get-ItemProperty -Path $winlogon -Name Userinit -ErrorAction SilentlyContinue).Userinit
Probe 'Winlogon Shell' {
    New-ItemProperty -Path $winlogon -Name Shell -Value ('explorer.exe,"{0}" shell' -f $marker) -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $winlogon -Name Shell -ErrorAction SilentlyContinue).Shell -match 'WenleTest' } {
    if ($shell) { New-ItemProperty -Path $winlogon -Name Shell -Value $shell -PropertyType String -Force | Out-Null }
    else { Remove-ItemProperty -Path $winlogon -Name Shell -Force -ErrorAction SilentlyContinue }
}

Probe 'Winlogon Userinit' {
    New-ItemProperty -Path $winlogon -Name Userinit -Value ('C:\Windows\system32\userinit.exe,"{0}" userinit' -f $marker) -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $winlogon -Name Userinit -ErrorAction SilentlyContinue).Userinit -match 'WenleTest' } {
    if ($userinit) { New-ItemProperty -Path $winlogon -Name Userinit -Value $userinit -PropertyType String -Force | Out-Null }
}

# ---------------------------------------------------------------- IFEO
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe'
Probe 'IFEO debugger' {
    New-Item -Path $ifeo -Force | Out-Null
    New-ItemProperty -Path $ifeo -Name Debugger -Value $marker -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $ifeo -Name Debugger -ErrorAction SilentlyContinue).Debugger -match 'WenleTest' } {
    Remove-Item -Path $ifeo -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- boot execute
$sessionManager = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$bootExecute = (Get-ItemProperty -Path $sessionManager -Name BootExecute -ErrorAction SilentlyContinue).BootExecute
Probe 'BootExecute' {
    New-ItemProperty -Path $sessionManager -Name BootExecute -Value @('autocheck autochk *', $marker) -PropertyType MultiString -Force | Out-Null
} { ((Get-ItemProperty -Path $sessionManager -Name BootExecute -ErrorAction SilentlyContinue).BootExecute -join ';') -match 'WenleTest' } {
    if ($bootExecute) { New-ItemProperty -Path $sessionManager -Name BootExecute -Value $bootExecute -PropertyType MultiString -Force | Out-Null }
}

# ---------------------------------------------------------------- AppInit
$appInit = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
$appInitValue = (Get-ItemProperty -Path $appInit -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs
Probe 'AppInit_DLLs' {
    New-ItemProperty -Path $appInit -Name AppInit_DLLs -Value $marker -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $appInit -Name LoadAppInit_DLLs -Value 1 -PropertyType DWord -Force | Out-Null
} { (Get-ItemProperty -Path $appInit -Name AppInit_DLLs -ErrorAction SilentlyContinue).AppInit_DLLs -match 'WenleTest' } {
    if ($null -ne $appInitValue) { New-ItemProperty -Path $appInit -Name AppInit_DLLs -Value $appInitValue -PropertyType String -Force | Out-Null }
    else { Remove-ItemProperty -Path $appInit -Name AppInit_DLLs -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- Active Setup
$activeSetup = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\WenleProbe'
Probe 'Active Setup StubPath' {
    New-Item -Path $activeSetup -Force | Out-Null
    New-ItemProperty -Path $activeSetup -Name StubPath -Value $payload -PropertyType String -Force | Out-Null
} { (Get-ItemProperty -Path $activeSetup -Name StubPath -ErrorAction SilentlyContinue).StubPath -match 'marker' } {
    Remove-Item -Path $activeSetup -Recurse -Force -ErrorAction SilentlyContinue
}

Say 'probe suite complete'
