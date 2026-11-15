# Install Wenle EDR in a guest.
#
# Run this inside the virtual machine, elevated, from the folder `stage.ps1`
# produced. It enables test signing if it is not already on, trusts the test
# certificate, places the driver and the service, registers both, and starts
# them. A guest that is not in test-signing mode cannot load a self-signed
# driver, so that is checked first and the script says what to do rather than
# failing at `fltmc load` with a number.

param(
    # The stage root, not this script's folder: the certificate and the
    # driver sit beside `tools`, and this file is two levels down.
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

function Fail([string]$why) { Write-Error $why; exit 1 }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run this from an elevated PowerShell'
}

# The old driver, when this is a reinstall, enforces the product's write gate:
# it refuses writes into C:\WenleAV for every process, administrators included,
# and an undeletable file owned by the user is exactly that. The service and the
# filter go first.
Get-Process -Name 'wenle-av-service*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
if (fltmc filters 2>$null | Select-String 'WenleAvFilter') {
    fltmc unload WenleAvFilter 2>&1 | Out-Null
    Start-Sleep -Seconds 2
}

# An earlier attempt may have left the product directory owned by SYSTEM with
# Administrators denied, or a service holding the old binary; both make the copy
# below an access denial with no explanation in the message.
$productDir = 'C:\WenleAV'
if (Test-Path $productDir) {
    takeown /f $productDir /r /d Y 2>$null | Out-Null
    icacls $productDir /grant '*S-1-5-32-544:F' /t 2>$null | Out-Null
}
$existingService = Get-Service -Name 'WenleAvService' -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -ne 'Stopped') {
    sc.exe stop WenleAvService 2>&1 | Out-Null
    Start-Sleep -Seconds 3
}
if (Test-Path (Join-Path $productDir 'wenle-av-service.exe')) {
    Remove-Item (Join-Path $productDir 'wenle-av-service.exe') -Force -ErrorAction SilentlyContinue
}

$signing = bcdedit /enum '{current}' 2>$null | Select-String 'testsigning'
if (-not ($signing -and $signing.Line -match 'Yes')) {
    Write-Output 'enabling test signing; the guest must be restarted and this script run again'
    bcdedit /set testsigning on | Out-Null
    Write-Output 'restart the guest, then run this script again'
    exit 2
}

$certificate = Join-Path $Root 'wenle-test-driver.cer'
if (-not (Test-Path $certificate)) { Fail "no test certificate at $certificate" }
Import-Certificate -FilePath $certificate -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
Import-Certificate -FilePath $certificate -CertStoreLocation 'Cert:\LocalMachine\TrustedPublisher' | Out-Null
Write-Output 'test certificate trusted'

$driver = Join-Path $Root 'WenleAvFilter.sys'
if (-not (Test-Path $driver)) { Fail "no driver at $driver" }
Copy-Item $driver 'C:\Windows\System32\drivers\WenleAvFilter.sys' -Force
Write-Output 'driver placed'

New-Item -ItemType Directory -Path 'C:\WenleAV' -Force | Out-Null
New-Item -ItemType Directory -Path 'C:\ProgramData\WenleAV\logs' -Force | Out-Null
New-Item -ItemType Directory -Path 'C:\ProgramData\WenleAV\models' -Force | Out-Null
Copy-Item (Join-Path $Root 'wenle-av-service.exe') 'C:\WenleAV\wenle-av-service.exe' -Force
Write-Output 'service placed'

# The minifilter is a filesystem service: `sc create` with type= filesystem is
# what makes `fltmc load` find it, and `start= system` loads it at boot.
$existing = Get-Service -Name 'WenleAvFilter' -ErrorAction SilentlyContinue
if (-not $existing) {
    sc.exe create WenleAvFilter type= filesystem start= system binPath= '\SystemRoot\System32\drivers\WenleAvFilter.sys' | Out-Null
}
sc.exe config WenleAvFilter type= filesystem start= system binPath= '\SystemRoot\System32\drivers\WenleAvFilter.sys' | Out-Null

$existing = Get-Service -Name 'WenleAvService' -ErrorAction SilentlyContinue
if (-not $existing) {
    sc.exe create WenleAvService type= own start= auto binPath= '"C:\WenleAV\wenle-av-service.exe"' | Out-Null
}
sc.exe config WenleAvService type= own start= auto binPath= '"C:\WenleAV\wenle-av-service.exe"' | Out-Null
sc.exe failure WenleAvService reset= 0 actions= '' | Out-Null

# The service reads its behaviour-log path from its own environment; a service
# does not see machine environment changes made after it was created.
$key = 'HKLM\SYSTEM\CurrentControlSet\Services\WenleAvService'
reg add $key /v Environment /t REG_MULTI_SZ /d "WENLE_BEHAVIOUR_LOG=C:\ProgramData\WenleAV\logs\behaviour.log\0WENLE_BEHAVIOUR_LOG_MAX=268435456" /f | Out-Null

if (-not (fltmc filters 2>$null | Select-String 'WenleAvFilter')) {
    fltmc load WenleAvFilter 2>&1 | Out-Null
}
Start-Sleep -Seconds 2
if (-not (fltmc filters 2>$null | Select-String 'WenleAvFilter')) {
    Fail 'the driver did not load; check that the guest is in test-signing mode and the certificate is trusted'
}
Write-Output 'driver loaded'

sc.exe stop WenleAvService 2>&1 | Out-Null
Start-Sleep -Seconds 2
sc.exe start WenleAvService 2>&1 | Out-Null
Start-Sleep -Seconds 6
$state = (sc.exe query WenleAvService | Select-String 'STATE').Line.Trim()
Write-Output "service: $state"
if ($state -notmatch 'RUNNING') { Fail 'the service did not reach RUNNING; see C:\ProgramData\WenleAV\logs\service.log' }

Write-Output ''
Write-Output 'installed. Next:'
Write-Output '  powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm-kit\collect.ps1 -Rounds 2'
