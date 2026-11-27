# Fetches the YARA-Forge rule package, compiles it into this product's database,
# and puts the database where the service reads it.
#
# The product ships no rules. They are somebody else's work under somebody else's
# licence, and this repository distributes code only; the rules are obtained here,
# by you, from the people who publish them.
#
# Run elevated: it writes under %ProgramData% and stops the service while the
# database it has open is replaced.

param(
    [ValidateSet('extended', 'core', 'full')]
    [string]$Tier = 'extended',
    [string]$Cli = 'C:\WenleAV\wenle.exe',
    [string]$DataDir = 'C:\ProgramData\WenleAV',
    [string]$Source,
    [string]$ServiceName = 'WenleAvService',
    [switch]$KeepSource
)

$ErrorActionPreference = 'Stop'

function Say([string]$text) { Write-Host $text }

if (-not (Test-Path $Cli)) { throw "no command-line tool at $Cli; pass -Cli <path>" }
if (-not (Test-Path (Join-Path $DataDir 'db'))) { throw "$DataDir\db does not exist; install the product first" }

$work = Join-Path $env:TEMP ("wenle-rules-" + [guid]::NewGuid().ToString('n').Substring(0, 8))
New-Item -ItemType Directory -Path $work -Force | Out-Null

try {
    if ($Source) {
        # A directory of rule sources, or a single .yar file, of the user's own.
        $sourcePath = $Source
        Say "using the rules at $sourcePath"
    } else {
        Say "asking github for the latest YARA-Forge release ..."
        $release = Invoke-RestMethod -Uri 'https://api.github.com/repos/YARAHQ/yara-forge/releases/latest' -UseBasicParsing
        $assetName = "yara-forge-rules-$Tier.zip"
        $asset = $release.assets | Where-Object { $_.name -eq $assetName } | Select-Object -First 1
        if (-not $asset) {
            throw "release $($release.tag_name) has no $assetName; it lists: " + (($release.assets | ForEach-Object { $_.name }) -join ', ')
        }
        $zip = Join-Path $work $assetName
        Say "downloading $assetName ($([math]::Round($asset.size/1MB,1)) MB) from $($release.tag_name)"
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath (Join-Path $work 'unpacked') -Force
        $sourcePath = Get-ChildItem (Join-Path $work 'unpacked') -Recurse -Filter '*.yar' |
            Sort-Object Length -Descending | Select-Object -First 1 -ExpandProperty FullName
        if (-not $sourcePath) { throw "no .yar file inside $assetName" }
        Say "unpacked: $sourcePath"
    }

    $database = Join-Path $DataDir 'db\rules.avdb'
    $backup = Join-Path $DataDir 'db\rules.avdb.before-fetch'
    if (Test-Path $database) {
        Copy-Item $database $backup -Force
        Say "the database in use was copied to $backup"
    }

    $running = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($running -and $running.Status -eq 'Running') {
        Say "stopping $ServiceName so the database is not in use"
        Stop-Service -Name $ServiceName -Force
        $waited = 0
        while ((Get-Process -Name 'wenle-av-service' -ErrorAction SilentlyContinue) -and $waited -lt 90) {
            Start-Sleep -Seconds 2
            $waited += 2
        }
    }

    Say 'compiling ...'
    & $Cli build $sourcePath --report
    $code = $LASTEXITCODE

    if ($running) {
        Say "starting $ServiceName"
        Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    }

    if ($code -ne 0) { throw "the compiler exited $code" }
    if (-not (Test-Path $database)) { throw "the compiler reported success but $database is not there" }

    Say ''
    Say ("written: {0} ({1:N1} MB)" -f $database, ((Get-Item $database).Length / 1MB))
    Say ("rules  : " + ((& $Cli db info 2>&1 | Select-String 'rules' | Select-Object -First 1) -replace '\s+', ' ').Trim())
    Say ''
    Say 'The rules you just compiled belong to their upstream authors under their'
    Say 'own licences, not to this project. Do not redistribute the database.'
} finally {
    if (-not $KeepSource) {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Say "the downloaded rules were kept at $work"
    }
}
