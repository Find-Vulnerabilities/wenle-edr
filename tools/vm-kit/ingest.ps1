# Bring a guest collection back to the host.
#
# The guest's log is the same shape as the host's: a line per event, `pid ppid
# wall f0..f34`, with the labels' windows referring to the same clock. This
# unpacks the zip, checks both halves are present and plausible, and prints what
# it found -- so that a broken collection is discovered here rather than after a
# training run that learned nothing.

param(
    [Parameter(Mandatory = $true)][string]$Zip,
    [string]$Destination = (Join-Path $PSScriptRoot '..\..\target\vm-collections')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path $Zip)) { throw "no collection at $Zip" }
New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$folder = Join-Path $Destination ([System.IO.Path]::GetFileNameWithoutExtension($Zip))
if (Test-Path $folder) { Remove-Item $folder -Recurse -Force }
Expand-Archive -Path $Zip -DestinationPath $folder -Force

$log = Join-Path $folder 'behaviour.log'
$labels = Join-Path $folder 'labels.csv'
if (-not (Test-Path $log)) { throw "the collection has no behaviour.log" }
if (-not (Test-Path $labels)) { throw "the collection has no labels.csv" }

$lines = (Get-Content $log | Measure-Object -Line).Lines
if ($lines -lt 1000) { throw "behaviour.log has only $lines lines; that is not a collection" }
$first = Get-Content $log -TotalCount 1
$fields = ($first -split '\s+').Count
if ($fields -lt 38) { throw "a log line has $fields fields, expected 38 (pid, ppid, wall, 35 features)" }
$windows = (Get-Content $labels | Measure-Object -Line).Lines
$families = Get-Content $labels | Select-Object -Skip 1 | ForEach-Object { ($_ -split ',')[3] } | Sort-Object -Unique
Write-Output ("collection unpacked to {0}" -f $folder)
Write-Output ("behaviour.log: {0} lines, {1:N1} MB" -f $lines, ((Get-Item $log).Length / 1MB))
Write-Output ("labels: {0} windows, families: {1}" -f $windows, ($families -join ', '))
