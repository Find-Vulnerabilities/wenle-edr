# Rebuild the rule database from the public feed plus this project's own rules.
#
# The feed's own updater replaces rules.avdb, which would drop everything in
# rules/local. This script is the one command that puts both back together:
# download the feed, compile it beside rules/local, replace the installed
# database, restart the service.
#
# Run elevated. The previous database is kept as rules.avdb.before-local.
param(
    [ValidateSet('extended', 'core', 'full')]
    [string]$Tier = 'extended',
    [string]$Cli = 'C:\WenleAV\wenle.exe',
    [string]$DataDir = 'C:\ProgramData\WenleAV',
    [string]$LocalRules,
    [string]$ServiceName = 'WenleAvService'
)

$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSScriptRoot
if (-not $LocalRules) { $LocalRules = Join-Path $repo 'rules\local' }
if (-not (Test-Path $LocalRules)) { throw "no local rules at $LocalRules" }
if (-not (Test-Path $Cli)) { throw "no command-line tool at $Cli" }

$work = Join-Path $env:TEMP ("wenle-rebuild-" + [guid]::NewGuid().ToString('n').Substring(0, 8))
$combined = Join-Path $work 'combined'
New-Item -ItemType Directory -Path $combined -Force | Out-Null

try {
    Write-Host "asking github for the latest YARA-Forge $Tier release ..."
    $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest' -UseBasicParsing
    $assetName = "yara-forge-rules-$Tier.zip"
    $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
    if (-not $asset) { throw "release $($release.tag_name) has no $assetName" }
    $zip = Join-Path $work $assetName
    Write-Host "downloading $assetName ($([math]::Round($asset.size/1MB,1)) MB) from $($release.tag_name)"
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath (Join-Path $work 'unpacked') -Force
    $feed = Get-ChildItem (Join-Path $work 'unpacked') -Recurse -Filter '*.yar' |
        Sort-Object Length -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $feed) { throw "no .yar file inside $assetName" }
    Copy-Item $feed (Join-Path $combined 'feed.yar') -Force
    Copy-Item (Join-Path $LocalRules '*') $combined -Force
    Write-Host "combined: 1 feed + $((Get-ChildItem $LocalRules -File | Measure-Object).Count) local source(s)"

    $database = Join-Path $DataDir 'db\rules.avdb'
    $backup = Join-Path $DataDir 'db\rules.avdb.before-local'
    if (Test-Path $database) { Copy-Item $database $backup -Force }

    $built = Join-Path $work 'rules.avdb'
    Write-Host 'compiling ...'
    & $Cli build $combined -o $built
    if ($LASTEXITCODE -ne 0) { throw "build failed with $LASTEXITCODE" }

    $running = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($running -and $running.Status -eq 'Running') {
        Write-Host "stopping $ServiceName"
        Stop-Service -Name $ServiceName -Force
        $waited = 0
        while ((Get-Process -Name 'wenle-av-service' -ErrorAction SilentlyContinue) -and $waited -lt 90) {
            Start-Sleep -Seconds 2
            $waited += 2
        }
    }
    Copy-Item $built $database -Force
    Write-Host "installed: $database"
} finally {
    $running = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($running -and $running.Status -ne 'Running') {
        Write-Host "starting $ServiceName"
        Start-Service -Name $ServiceName
    }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
