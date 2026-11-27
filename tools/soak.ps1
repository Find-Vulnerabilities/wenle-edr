#requires -RunAsAdministrator
<#
.SYNOPSIS
  Long-running stability soak for Wenle AV on this host and, optionally, in the
  test VM.

.DESCRIPTION
  Every minute it records the service's memory, handles, threads, scan counters,
  alert/quarantine counts, canary count and bugcheck count. Every few minutes it
  puts the product under work: file churn in a watched folder, a synthetic
  archive the watcher must take, a canary touch the canary monitor must report,
  a driver-directory scan, and occasionally a service restart.

  Nothing malicious is executed. The synthetic archive contains an inert file
  whose bytes match the MEMZ signature; it is written, scanned and quarantined,
  never run.

  The output is one CSV per side plus a transcript, under
  -OutputDirectory. The script is meant to be started as a background job and
  left alone; it never prompts.

.PARAMETER Hours
  How long to run. Default 2.

.PARAMETER SkipVm
  Host only.

.PARAMETER VmCredential
  Credential for the VM's WinRM endpoint (192.168.129.129 by default).
#>
param(
    [double]$Hours = 2,
    [switch]$SkipVm,
    [System.Management.Automation.PSCredential]$VmCredential,
    [string]$VmAddress = '192.168.129.129',
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE 'Downloads\wenle-soak-results')
)

$ErrorActionPreference = 'Continue'
$deadline = (Get-Date).AddHours($Hours)
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$hostCsv = Join-Path $OutputDirectory "host-$stamp.csv"
$vmCsv = Join-Path $OutputDirectory "vm-$stamp.csv"
$transcript = Join-Path $OutputDirectory "soak-$stamp.log"

function Log([string]$line) {
    $entry = "{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $line
    Add-Content -Path $transcript -Value $entry
    Write-Output $entry
}

function Write-Row([string]$csv, [hashtable]$row) {
    if (-not (Test-Path $csv)) {
        ($row.Keys | Sort-Object) -join ',' | Set-Content -Path $csv -Encoding ASCII
    }
    ($row.Keys | Sort-Object | ForEach-Object { $row[$_] }) -join ',' |
        Add-Content -Path $csv -Encoding ASCII
}

function Get-MetricsHost {
    $service = Get-Service WenleAvService -ErrorAction SilentlyContinue
    $cim = Get-CimInstance Win32_Process -Filter "Name='wenle-av-service.exe'" -ErrorAction SilentlyContinue
    $process = if ($cim) { Get-Process -Id $cim.ProcessId -ErrorAction SilentlyContinue } else { $null }
    $status = & 'C:\WenleAV\wenle.exe' service status 2>&1 | Out-String
    $examined = if ($status -match 'files examined\s+(\d+)') { $Matches[1] } else { '' }
    $scans = if ($status -match 'scans running\s+(\d+)') { $Matches[1] } else { '' }
    $driver = if ($status -match 'driver\s+loaded') { 'loaded' } else { 'not-loaded' }
    $bugchecks = (Get-WinEvent -FilterHashtable @{
        LogName = 'System'; Id = 1001
        StartTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    } -ErrorAction SilentlyContinue | Measure-Object).Count
    $crashes = (Get-WinEvent -FilterHashtable @{
        LogName = 'System'; StartTime = (Get-Date).AddMinutes(-5)
    } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 7031, 7034 }).Count
    $alerts = if (Test-Path 'C:\ProgramData\WenleAV\alerts.jsonl') {
        (Get-Content 'C:\ProgramData\WenleAV\alerts.jsonl' -ErrorAction SilentlyContinue | Measure-Object).Count
    } else { 0 }
    $items = if (Test-Path 'C:\ProgramData\WenleAV\quarantine\items') {
        (Get-ChildItem 'C:\ProgramData\WenleAV\quarantine\items' -File -ErrorAction SilentlyContinue | Measure-Object).Count
    } else { 0 }
    $canaries = (Get-ChildItem 'C:\Users\wensz\Desktop','C:\Users\wensz\Documents','C:\Users\wensz\Pictures','C:\Users\wensz\Downloads' -Filter '~wenle-canary-*' -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    [ordered]@{
        when = (Get-Date -Format 's')
        side = 'host'
        state = if ($service) { $service.Status } else { 'missing' }
        pid = if ($cim) { $cim.ProcessId } else { 0 }
        ws_mb = if ($process) { [math]::Round($process.WorkingSet64 / 1MB) } else { 0 }
        private_mb = if ($process) { [math]::Round($process.PrivateMemorySize64 / 1MB) } else { 0 }
        handles = if ($process) { $process.HandleCount } else { 0 }
        threads = if ($process) { $process.Threads.Count } else { 0 }
        cpu_s = if ($process) { [math]::Round($process.CPU) } else { 0 }
        files_examined = $examined
        scans_running = $scans
        driver = $driver
        bugchecks = $bugchecks
        crashes_5m = $crashes
        alerts = $alerts
        quarantine_items = $items
        canaries = $canaries
    }
}

function Get-MetricsVm($session) {
    Invoke-Command -Session $session -ScriptBlock {
        $service = Get-Service WenleAvService -ErrorAction SilentlyContinue
        $cim = Get-CimInstance Win32_Process -Filter "Name='wenle-av-service.exe'" -ErrorAction SilentlyContinue
        $process = if ($cim) { Get-Process -Id $cim.ProcessId -ErrorAction SilentlyContinue } else { $null }
        $status = & 'C:\WenleAV\wenle.exe' service status 2>&1 | Out-String
        $examined = if ($status -match 'files examined\s+(\d+)') { $Matches[1] } else { '' }
        $scans = if ($status -match 'scans running\s+(\d+)') { $Matches[1] } else { '' }
        $driver = if ($status -match 'driver\s+loaded') { 'loaded' } else { 'not-loaded' }
        $bugchecks = (Get-WinEvent -FilterHashtable @{
            LogName = 'System'; Id = 1001
            StartTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        } -ErrorAction SilentlyContinue | Measure-Object).Count
        $crashes = (Get-WinEvent -FilterHashtable @{
            LogName = 'System'; StartTime = (Get-Date).AddMinutes(-5)
        } -ErrorAction SilentlyContinue | Where-Object { $_.Id -in 7031, 7034 }).Count
        $alerts = if (Test-Path 'C:\ProgramData\WenleAV\alerts.jsonl') {
            (Get-Content 'C:\ProgramData\WenleAV\alerts.jsonl' -ErrorAction SilentlyContinue | Measure-Object).Count
        } else { 0 }
        $items = if (Test-Path 'C:\ProgramData\WenleAV\quarantine\items') {
            (Get-ChildItem 'C:\ProgramData\WenleAV\quarantine\items' -File -ErrorAction SilentlyContinue | Measure-Object).Count
        } else { 0 }
        $canaries = (Get-ChildItem 'C:\Users\wensz\Desktop','C:\Users\wensz\Documents','C:\Users\wensz\Pictures','C:\Users\wensz\Downloads' -Filter '~wenle-canary-*' -Force -ErrorAction SilentlyContinue | Measure-Object).Count
        [ordered]@{
            when = (Get-Date -Format 's'); side = 'vm'
            state = if ($service) { $service.Status } else { 'missing' }
            pid = if ($cim) { $cim.ProcessId } else { 0 }
            ws_mb = if ($process) { [math]::Round($process.WorkingSet64 / 1MB) } else { 0 }
            private_mb = if ($process) { [math]::Round($process.PrivateMemorySize64 / 1MB) } else { 0 }
            handles = if ($process) { $process.HandleCount } else { 0 }
            threads = if ($process) { $process.Threads.Count } else { 0 }
            cpu_s = if ($process) { [math]::Round($process.CPU) } else { 0 }
            files_examined = $examined; scans_running = $scans; driver = $driver
            bugchecks = $bugchecks; crashes_5m = $crashes; alerts = $alerts
            quarantine_items = $items; canaries = $canaries
        }
    }
}

function Invoke-HostWorkload([int]$iteration) {
    $start = Get-Date
    $root = Join-Path $env:USERPROFILE 'Downloads\wenle-soak'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    for ($i = 1; $i -le 80; $i++) {
        $file = Join-Path $root ("churn-{0}-{1}.txt" -f $iteration, $i)
        Set-Content -Path $file -Value ("soak {0} {1}" -f $iteration, $i) -Encoding ASCII
        if ($i % 2 -eq 0) { Move-Item $file ($file + '.log') -Force }
    }
    Get-ChildItem $root -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'churn-*' } |
        Select-Object -First 60 | Remove-Item -Force -ErrorAction SilentlyContinue
    if ($iteration % 10 -eq 0) {
        $stage = Join-Path $root 'stage.exe'
        [byte[]]$bytes = [Text.Encoding]::ASCII.GetBytes('MZ' + ('A' * 4096) + 'MEMZ' + ('B' * 64) + 'PhysicalDrive')
        [IO.File]::WriteAllBytes($stage, $bytes)
        $zip = Join-Path $env:USERPROFILE ("Downloads\soak-archive-{0}.zip" -f $iteration)
        Compress-Archive -Path $stage -DestinationPath $zip -Force
        Remove-Item $stage -Force -ErrorAction SilentlyContinue
    }
    if ($iteration % 8 -eq 0) {
        $canary = Get-ChildItem 'C:\Users\wensz\Desktop','C:\Users\wensz\Documents','C:\Users\wensz\Pictures' -Filter '~wenle-canary-*' -Force -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($canary) { Add-Content -Path $canary.FullName -Value 'soak-touch' -Force -ErrorAction SilentlyContinue }
    }
    if ($iteration % 15 -eq 0) {
        & 'C:\WenleAV\wenle.exe' scan 'C:\Windows\System32\drivers' -q 2>&1 | Out-Null
    }
    if ($iteration % 45 -eq 0) {
        & 'C:\WenleAV\wenle.exe' service stop 2>&1 | Out-Null
        Start-Sleep -Seconds 6
        $started = $false
        for ($attempt = 0; $attempt -lt 3 -and -not $started; $attempt++) {
            & 'C:\WenleAV\wenle.exe' service start 2>&1 | Out-Null
            Start-Sleep -Seconds 8
            $started = (Get-Service WenleAvService -ErrorAction SilentlyContinue).Status -eq 'Running'
            if (-not $started) { Start-Sleep -Seconds 4 }
        }
        if (-not $started) { Log "restart: service did not come back after stop" }
    }
    [math]::Round(((Get-Date) - $start).TotalMilliseconds)
}

function Invoke-VmWorkload($session, [int]$iteration) {
    Invoke-Command -Session $session -ScriptBlock {
        param($iteration)
        $start = Get-Date
        $root = 'C:\Users\wensz\Downloads\wenle-soak'
        New-Item -ItemType Directory -Path $root -Force | Out-Null
        for ($i = 1; $i -le 40; $i++) {
            $file = Join-Path $root ("churn-{0}-{1}.txt" -f $iteration, $i)
            Set-Content -Path $file -Value ("soak {0} {1}" -f $iteration, $i) -Encoding ASCII
        }
        Get-ChildItem $root -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like 'churn-*' } |
            Select-Object -First 30 | Remove-Item -Force -ErrorAction SilentlyContinue
        if ($iteration % 12 -eq 0) {
            $canary = Get-ChildItem 'C:\Users\wensz\Desktop','C:\Users\wensz\Documents','C:\Users\wensz\Pictures' -Filter '~wenle-canary-*' -Force -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($canary) { Add-Content -Path $canary.FullName -Value 'vm-soak-touch' -Force -ErrorAction SilentlyContinue }
        }
        if ($iteration % 20 -eq 0) {
            & 'C:\WenleAV\wenle.exe' scan 'C:\Windows\System32\drivers' -q 2>&1 | Out-Null
        }
        [math]::Round(((Get-Date) - $start).TotalMilliseconds)
    } -ArgumentList $iteration
}

Log "soak starting for $Hours hour(s); host csv $hostCsv; vm csv $vmCsv"
$vmSession = $null
if (-not $SkipVm -and $VmCredential) {
    try {
        $vmSession = New-PSSession -ComputerName $VmAddress -Credential $VmCredential -Authentication Negotiate -ErrorAction Stop
        Log "vm session opened"
    } catch {
        Log "vm session failed: $($_.Exception.Message)"
    }
}

$iteration = 0
while ((Get-Date) -lt $deadline) {
    $iteration++
    $hostWork = 0
    $vmWork = 0
    try { $hostWork = Invoke-HostWorkload $iteration } catch { Log "host workload failed: $($_.Exception.Message)" }
    $hostRow = Get-MetricsHost
    $hostRow['iteration'] = $iteration
    $hostRow['work_ms'] = $hostWork
    Write-Row $hostCsv $hostRow
    if ($vmSession) {
        try {
            $vmWork = Invoke-VmWorkload $vmSession $iteration
            $vmRow = Get-MetricsVm $vmSession
            $vmRow['iteration'] = $iteration
            $vmRow['work_ms'] = $vmWork
            Write-Row $vmCsv $vmRow
        } catch {
            Log "vm iteration failed: $($_.Exception.Message)"
            try {
                Remove-PSSession $vmSession -ErrorAction SilentlyContinue
                $vmSession = New-PSSession -ComputerName $VmAddress -Credential $VmCredential -Authentication Negotiate -ErrorAction Stop
            } catch { Log "vm reconnect failed: $($_.Exception.Message)"; $vmSession = $null }
        }
    }
    if ($iteration % 15 -eq 0) {
        Log ("iteration {0}: host ws={1} MB handles={2} threads={3} examined={4} alerts={5} bugchecks={6}; vm ws={7} handles={8}" -f `
            $iteration, $hostRow['ws_mb'], $hostRow['handles'], $hostRow['threads'], $hostRow['files_examined'], $hostRow['alerts'], $hostRow['bugchecks'], `
            $(if ($vmRow) { $vmRow['ws_mb'] } else { 'n/a' }), $(if ($vmRow) { $vmRow['handles'] } else { 'n/a' }))
    }
    Start-Sleep -Seconds (60 - ((Get-Date).Second))
}
if ($vmSession) { Remove-PSSession $vmSession -ErrorAction SilentlyContinue }
Log "soak finished after $iteration iteration(s)"
