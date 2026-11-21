<#
.SYNOPSIS
    Update the sandbox (Speakeasy and its wheels) without touching the rest of
    the product.

.DESCRIPTION
    The sandbox lives in its own Python environment under
    %ProgramData%\WenleAV\sandbox\venv so that updating it cannot break the
    service, and so that it can be updated on a machine where nothing else is
    allowed to change.

    Two sources are supported:

    * a folder that holds `manifest.json` and the wheel files it names. This is
      the offline case: copy the folder onto the machine (USB, network share)
      and run this script, or let the scheduled task pick it up.
    * an HTTP(S) URL to the same manifest. The wheels are named inside it and
      downloaded next to it.

    The manifest is:

        {
          "speakeasy_version": "2.1.0",
          "wheels": [
            {"file": "speakeasy_emulator-2.1.0-py3-none-any.whl", "sha256": "..."},
            {"file": "unicorn-2.1.4-cp37-abi3-win_amd64.whl", "sha256": "..."}
          ]
        }

    Every wheel is checked against its SHA-256 before it is installed, and the
    version in the manifest is compared with the one installed; an older or equal
    manifest does nothing and says so.

.PARAMETER Source
    A folder or an HTTP(S) URL holding manifest.json.

.PARAMETER InstallDir
    The sandbox's state directory. Default: %ProgramData%\WenleAV\sandbox.

.PARAMETER Offline
    Refuse to fall back to the Python package index. The default is to bootstrap
    from the index when the environment does not exist yet and no wheels were
    supplied.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\sandbox_update.ps1 -Source C:\sandbox-updates
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Source,
    [string] $InstallDir = "$env:ProgramData\WenleAV\sandbox",
    [switch] $Offline,
    [string] $Python = "python"
)

$ErrorActionPreference = 'Stop'

function Write-Log([string] $Message) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Add-Content -Path (Join-Path $InstallDir 'update.log') -Value $line
    Write-Output $line
}

function Get-Manifest {
    param([string] $Where)
    if ($Where -match '^https?://') {
        $text = (Invoke-WebRequest -Uri $Where -UseBasicParsing -TimeoutSec 60).Content
        return ($text | ConvertFrom-Json)
    }
    $path = Join-Path $Where 'manifest.json'
    if (-not (Test-Path $path)) {
        throw "no manifest.json in $Where"
    }
    return (Get-Content $path -Raw | ConvertFrom-Json)
}

function Get-Wheel {
    param([string] $Where, [string] $File, [string] $Hash)
    $name = Split-Path $File -Leaf
    $target = Join-Path $InstallDir ("packages\" + $name)
    New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
    if ($Where -match '^https?://') {
        Invoke-WebRequest -Uri ($Where.TrimEnd('/') + '/' + $name) -OutFile $target -UseBasicParsing -TimeoutSec 120
    } else {
        Copy-Item (Join-Path $Where $name) $target -Force
    }
    $actual = (Get-FileHash $target -Algorithm SHA256).Hash.ToLower()
    if ($Hash -and $actual -ne $Hash.ToLower()) {
        throw "hash mismatch for $name : $actual"
    }
    Write-Log "wheel $name sha256 $actual"
    return $target
}

function Get-InstalledVersion {
    param([string] $VenvPython)
    if (-not (Test-Path $VenvPython)) { return $null }
    $value = & $VenvPython -m pip show speakeasy-emulator 2>$null | Select-String '^Version:'
    if (-not $value) { return $null }
    return ($value -replace '^Version:\s*', '').Trim()
}

Write-Log "sandbox update started: source=$Source"

$manifest = Get-Manifest $Source
$version = [string] $manifest.speakeasy_version
if (-not $version) { throw 'the manifest has no speakeasy_version' }
Write-Log "manifest version $version"

$venv = Join-Path $InstallDir 'venv'
$venvPython = Join-Path $venv 'Scripts\python.exe'
$installed = Get-InstalledVersion $venvPython
Write-Log "installed version: $installed"

if ($installed -and ([version]$installed -ge [version]$version)) {
    Write-Log "nothing to do: installed $installed is not older than $version"
    exit 0
}

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$staging = Join-Path $InstallDir 'packages'
New-Item -ItemType Directory -Path $staging -Force | Out-Null

$wheels = @()
foreach ($wheel in @($manifest.wheels)) {
    if ($null -eq $wheel) { continue }
    $wheels += Get-Wheel -Where $Source -File $wheel.file -Hash $wheel.sha256
}

if (-not (Test-Path $venvPython)) {
    Write-Log "creating venv at $venv"
    & $Python -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'venv creation failed' }
}

if ($wheels.Count -gt 0) {
    Write-Log "installing $($wheels.Count) wheel(s) from the manifest"
    & $venvPython -m pip install --disable-pip-version-check --no-index --find-links $staging --upgrade @wheels
    if ($LASTEXITCODE -ne 0) { throw 'wheel install failed' }
} elseif (-not $Offline) {
    Write-Log 'no wheels in the manifest; installing from the package index'
    & $venvPython -m pip install --disable-pip-version-check --upgrade "speakeasy-emulator>=$version"
    if ($LASTEXITCODE -ne 0) { throw 'index install failed' }
} else {
    throw 'offline and no wheels in the manifest'
}

$final = Get-InstalledVersion $venvPython
Write-Log "installed version now: $final"
$state = @{
    speakeasy_version = $final
    updated_at = (Get-Date).ToString('o')
    source = $Source
}
$state | ConvertTo-Json | Set-Content -Path (Join-Path $InstallDir 'state.json') -Encoding ASCII
Write-Log 'sandbox update finished'
