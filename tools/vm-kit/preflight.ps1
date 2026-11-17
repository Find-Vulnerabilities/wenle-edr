# Before a collection, prove that the service is writing.
#
# The technique windows of 2026-11-17 produced two stories out of 223 because the
# service was not writing the behaviour log while they ran: the log has twelve
# thousand events in its first minute, then nothing until the service was
# restarted. A collection that cannot prove the log is growing is a collection
# that will produce labels with no events, so this refuses to pass in that state.

param(
    [string]$Log = 'C:\ProgramData\WenleAV\logs\behaviour.log',
    [int]$Seconds = 5
)

$ErrorActionPreference = 'Stop'

function Fail([string]$why) {
    Write-Error $why
    exit 1
}

$service = Get-Service -Name 'WenleAvService' -ErrorAction SilentlyContinue
if (-not $service) { Fail 'WenleAvService is not installed on this machine' }
if ($service.Status -ne 'Running') {
    Fail ("WenleAvService is $($service.Status); start it and run this again")
}

$driver = fltmc filters 2>$null | Select-String 'WenleAvFilter'
if (-not $driver) { Fail 'WenleAvFilter is not loaded; the driver collects the events the model is trained on' }

$model = Join-Path 'C:\ProgramData\WenleAV\models' 'behaviour.bin'
if (-not (Test-Path $model)) { Write-Output 'warning: no behaviour model installed; collection still works' }

if (-not (Test-Path $Log)) { Fail "no behaviour log at $Log (check WENLE_BEHAVIOUR_LOG in the service environment)" }

$before = (Get-Item $Log).Length
Start-Sleep -Seconds $Seconds
$after = (Get-Item $Log).Length
$rate = ($after - $before) / $Seconds
$events = 0.0
$line = Get-Content $Log -Tail 1 -ErrorAction SilentlyContinue
if ($line) {
    $fields = $line -split '\s+'
    if ($fields.Count -ge 3) { $events = [double]$fields[2] / 1e6 }
}

if ($after -le $before) {
    Fail ("the behaviour log did not grow in $Seconds s (size $after bytes); the service is running but not recording")
}

Write-Output ("service running, filter loaded, log growing at {0:N1} KB/s" -f ($rate / 1KB))
if ($events -gt 0) {
    Write-Output ("last event at {0}" -f [DateTimeOffset]::FromUnixTimeMilliseconds([long]($events * 1000)).LocalDateTime)
}
Write-Output 'collection may start'
exit 0
