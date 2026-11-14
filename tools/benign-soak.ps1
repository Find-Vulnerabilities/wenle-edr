# Run ordinary work for hours and count what the detectors fire on.
#
# The matrix answers "which family does each detector catch". This answers the
# other half of the question a user asks -- "will it bother me while I work" --
# by running the benign workloads a developer's machine actually performs and
# recording every detector hit that lands in the log during the interval.
#
# Hits are counted from the log by timestamp, never by offset: the service writes
# through a buffered logger and a byte count can be read before the line is
# flushed (measured on 2026-11-14).
#
# The soak runs a fixed number of rounds and stops. It is not a daemon: a script
# that quietly ran for ever would be the thing the product exists to stop.

param(
    [int]$Rounds = 30,
    [int]$PauseSeconds = 120,
    [string]$Out = 'C:\WenleAV\test\corpus\soak.csv'
)

$ErrorActionPreference = 'Continue'
$svc = 'C:\ProgramData\WenleAV\logs\service.log'
$ids = 'staged-and-run', 'document-spawned-script', 'persistence-arranged', 'mass-document-rename', 'ransomware-shape'
$repo = 'C:\Users\wensz\Downloads\wenle-av'

function Count-Since([datetime]$since) {
    $counts = @{}
    foreach ($id in $ids) { $counts[$id] = 0 }
    $floor = $since.AddSeconds(-1)
    foreach ($line in (Get-Content $svc -Tail 40000)) {
        if ($line.Length -lt 19) { continue }
        try { $stamp = [datetime]::Parse($line.Substring(0, 19)) } catch { continue }
        if ($stamp -lt $floor) { continue }
        foreach ($id in $ids) {
            if ($line.Contains("behaviour/$id")) { $counts[$id] += 1 }
        }
    }
    return $counts
}

if (-not (Test-Path $Out)) {
    'round,started,benign_scripts,benign_workload,' + ($ids -join ',') | Set-Content -Path $Out -Encoding ASCII
}

for ($round = 1; $round -le $Rounds; $round++) {
    $started = Get-Date
    & (Join-Path $repo 'tools\benign-scripts.ps1') 2>&1 | Out-Null
    & (Join-Path $repo 'tools\benign-workload.ps1') 2>&1 | Out-Null
    Start-Sleep -Seconds 3
    $counts = Count-Since $started
    $cells = foreach ($id in $ids) { $counts[$id] }
    $row = ('{0},{1},{2},{3},{4}' -f $round, $started.ToString('yyyy-MM-dd HH:mm:ss'), 1, 1, ($cells -join ','))
    Add-Content -Path $Out -Value $row -Encoding ASCII
    Write-Output $row
    if ($round -lt $Rounds) { Start-Sleep -Seconds $PauseSeconds }
}

'benign soak complete' | Add-Content $Out
