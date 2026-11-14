# Stresses the driver's connection path: unload and load it repeatedly, restart
# the service, and launch programs throughout, then optionally soak under load.
#
# Written for the VM. It prints one line per cycle and stops at the first sign of
# trouble: a bugcheck (the guest restarts and the script is gone), a gate that
# stopped answering, or a reload that failed.
#
#   .\WenleAV-reload-stress.ps1                 # 50 cycles, no soak
#   .\WenleAV-reload-stress.ps1 -SoakMinutes 30 # then 30 minutes under load
#   .\WenleAV-reload-stress.ps1 -Cycles 10 -Quick

param(
    [int]$Cycles = 50,
    [int]$SoakMinutes = 0,
    [int]$ConcurrentLaunches = 20,
    [string]$ServiceName = 'WenleAvService',
    [string]$FilterName = 'WenleAvFilter',
    [string]$Log = 'C:\ProgramData\WenleAV\logs\service.log',
    [switch]$Quick
)

$ErrorActionPreference = 'Continue'
$failures = 0
$transcriptPath = Join-Path $env:TEMP ("wenle-reload-stress-" + (Get-Date -Format 'yyyyMMdd-HHmmss') + ".txt")

function Report([string]$text, [string]$colour = 'Gray') {
    Write-Host $text -ForegroundColor $colour
    Add-Content -Path $transcriptPath -Value $text
}
function Fail([string]$text) {
    $script:failures++
    Report "FAIL: $text" 'Red'
}

Report "transcript: $transcriptPath"
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Report "boot: $boot"

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Report "no service named $ServiceName; install the product first" 'Red'
    exit 2
}

$testDir = Join-Path $env:TEMP 'wenle-stress'
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
$testExe = Join-Path $testDir 'probe.exe'
Copy-Item 'C:\Windows\System32\whoami.exe' $testExe -Force

function Decisions-Since([datetime]$since) {
    if (-not (Test-Path $Log)) { return 0 }
    $stamp = $since.ToString('yyyy-MM-dd HH:mm:ss')
    @(Get-Content $Log -ErrorAction SilentlyContinue | Where-Object {
        $_.Length -gt 19 -and $_.Substring(0, 19) -ge $stamp -and
        $_ -match 'filter_port:\d+ .*(was allowed|was refused|still running after|digest of a file found clean)'
    }).Count
}

function Launch-Probes([int]$count) {
    $procs = 1..$count | ForEach-Object {
        Start-Process $testExe -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 300
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

# ---------------------------------------------------------------- reload cycles
$ran = 0
for ($i = 1; $i -le $Cycles; $i++) {
    $ran = $i
    $before = Get-Date

    & fltmc unload $FilterName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "cycle ${i}: unload returned $LASTEXITCODE" }
    Start-Sleep -Milliseconds 500

    # Programs while the driver is gone: nothing may hang or crash.
    Launch-Probes 5

    & fltmc load $FilterName 2>&1 | Out-Null
    # Not a failure on its own: the service now notices the driver going away and
    # loads it again itself, so this call can lose the race and be told the
    # filter is already there. What matters is that the filter is loaded at the
    # end, not who loaded it.
    Start-Sleep -Milliseconds 500

    $loaded = (fltmc filters 2>&1 | Select-String $FilterName)
    if (-not $loaded) { Fail "cycle ${i}: the filter is not loaded after the load step" }

    # The question is not "did a line appear" but "does the gate answer again",
    # so this asks it directly: keep launching until a decision shows up in the
    # log, for at most thirty seconds. The reconnect loop backs off to fifteen
    # seconds when the filter has been gone for a while, so the wait has to be
    # generous; a fixed sleep measures the backoff instead of the product.
    $deadline = (Get-Date).AddSeconds(30)
    $decisions = 0
    while ((Get-Date) -lt $deadline) {
        Launch-Probes 3
        Start-Sleep -Milliseconds 700
        $decisions = Decisions-Since $before
        if ($decisions -gt 0) { break }
    }
    if ($decisions -eq 0) {
        Fail "cycle ${i}: the gate made no decision within 30 s of the reload (this is the bug)"
    }

    if ($i % 5 -eq 0) {
        $service = Get-Service -Name $ServiceName
        Report ("cycle {0,3}/{1}: {2}, decisions {3}" -f $i, $Cycles, $service.Status, $decisions)
    }

    if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime -gt $boot) {
        Report 'the guest restarted; a bugcheck took it down. Read C:\Windows\MEMORY.DMP' 'Red'
        exit 3
    }
    if ($Quick -and $i -ge 10) { break }
}

# --------------------------------------------------------- service restart loop
for ($i = 1; $i -le 5; $i++) {
    $before = Get-Date
    Restart-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    $waited = 0
    while ($waited -lt 60) {
        Start-Sleep -Seconds 1
        $waited++
        if ((Get-Service -Name $ServiceName).Status -eq 'Running') { break }
    }
    if ((Get-Service -Name $ServiceName).Status -ne 'Running') { Fail "restart ${i}: still not running after ${waited}s" }
    Launch-Probes $ConcurrentLaunches
    $decisions = Decisions-Since $before
    if ($decisions -eq 0) { Fail "restart ${i}: the gate made no decision after the restart" }
    Report "restart ${i}: running after ${waited}s, decisions ${decisions}"
}

# ---------------------------------------------------------------------- soak
if ($SoakMinutes -gt 0) {
    $service = Get-Process wenle-av-service -ErrorAction SilentlyContinue
    $startPrivate = if ($service) { $service.PrivateMemorySize64 } else { 0 }
    $startHandles = if ($service) { $service.HandleCount } else { 0 }
    Report "soaking for $SoakMinutes minutes under load ..."
    $end = (Get-Date).AddMinutes($SoakMinutes)
    while ((Get-Date) -lt $end) {
        Launch-Probes 3
        Start-Sleep -Seconds 5
    }
    $service = Get-Process wenle-av-service -ErrorAction SilentlyContinue
    if ($service) {
        $grewMb = ($service.PrivateMemorySize64 - $startPrivate) / 1MB
        $handles = $service.HandleCount - $startHandles
        Report ("soak: private {0:+0.0;-0.0} MB, handles {1:+0;-0}" -f $grewMb, $handles)
        if ($grewMb -gt ($SoakMinutes * 10)) { Fail "soak: private memory grew faster than 10 MB/minute" }
    } else {
        Fail 'soak: the service is gone'
    }
}

Report ''
if ($failures -eq 0) {
    Report "PASS: $ran reload cycles, 5 restarts, no missed decision and no restart" 'Green'
    exit 0
}
Report "FAILED: $failures problem(s); transcript at $transcriptPath" 'Red'
exit 1
