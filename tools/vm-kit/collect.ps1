# Collect behaviour in a guest with our own driver.
#
# Why a guest rather than the host: the techniques worth collecting are the ones
# a person would not run on their own machine, and the point of the collection is
# to see them as *this* driver reports them -- same features, same clock, same
# process identities as the service that will run the model. Public datasets are
# another machine's Sysmon and the measured transfer was 0.2 %.
#
# The script refuses to start without a working service and driver, because a
# collection that silently produces an empty log is worse than no collection: it
# is a corpus that teaches the model that nothing happens.

param(
    [int]$Rounds = 5,
    [string]$Output = 'C:\WenleAV\vm-collection',
    [string]$Corpus = (Join-Path $PSScriptRoot '..\behaviour-corpus.ps1')
)

$ErrorActionPreference = 'Stop'

function Fail([string]$why) {
    Write-Error $why
    exit 1
}

$service = Get-Service -Name 'WenleAvService' -ErrorAction SilentlyContinue
if (-not $service) {
    Fail 'WenleAvService is not installed in this guest; install the product first (see README.md).'
}
$driver = 'C:\WenleAV\wenle-av-service.exe'
if (-not (Test-Path $driver)) {
    Fail "the service binary is missing at $driver"
}
if (-not (Test-Path $Corpus)) {
    Fail "the corpus script is missing at $Corpus"
}

Write-Output 'starting the service'
if ($service.Status -ne 'Running') {
    Start-Service -Name 'WenleAvService'
    (Get-Service -Name 'WenleAvService').WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
$filters = fltmc filters 2>$null
if (-not ($filters -match 'WenleAvFilter')) {
    Write-Output 'loading the filter'
    fltmc load WenleAvFilter | Out-Null
    Start-Sleep -Seconds 3
}
$filters = fltmc filters 2>$null
if (-not ($filters -match 'WenleAvFilter')) {
    Fail 'the filter did not load; the service can run but no behaviour will be collected.'
}

New-Item -ItemType Directory -Path $Output -Force | Out-Null
$labels = Join-Path $Output 'labels.csv'
if (Test-Path $labels) { Remove-Item $labels -Force }

Write-Output "running $Rounds rounds of every family"
for ($round = 1; $round -le $Rounds; $round++) {
    Write-Output "round $round"
    & $Corpus 2>&1 | Out-Null
}

# The corpus families into the collection's labels first, then the ATT&CK
# techniques, which append theirs beside them.
$corpusLabels = 'C:\WenleAV\test\corpus\labels.csv'
if (Test-Path $corpusLabels) {
    Copy-Item $corpusLabels $labels -Force
}
Write-Output 'running ATT&CK techniques'
& (Join-Path $PSScriptRoot 'techniques.ps1') -Output $Output 2>&1 | Out-Null

$log = 'C:\ProgramData\WenleAV\logs\behaviour.log'
if (-not (Test-Path $log)) {
    Fail "no behaviour log at $log; the service is not collecting (check WENLE_BEHAVIOUR_LOG in the service environment)."
}
$size = (Get-Item $log).Length
if ($size -lt 1MB) {
    Fail "the behaviour log is only $size bytes; a collection this small cannot teach anything."
}

Copy-Item $log (Join-Path $Output 'behaviour.log') -Force
Copy-Item 'C:\ProgramData\WenleAV\logs\service.log' (Join-Path $Output 'service.log') -Force
# $labels is already $Output\labels.csv -- the corpus copy and the techniques
# appended their rows to it -- so copying it there is copying a file onto itself.
if (-not (Test-Path $labels)) {
    $corpusLabels = 'C:\WenleAV\test\corpus\labels.csv'
    if (Test-Path $corpusLabels) { Copy-Item $corpusLabels $labels -Force }
}

$zip = Join-Path $Output ("collection-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
Compress-Archive -Path (Join-Path $Output 'behaviour.log'), (Join-Path $Output 'service.log'), (Join-Path $Output 'labels.csv') -DestinationPath $zip -Force
Write-Output ("collection written to {0} ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB))
