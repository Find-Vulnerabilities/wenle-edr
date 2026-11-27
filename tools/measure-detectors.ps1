# Measure each behaviour family against each detector, one at a time.
#
# The corpus runner records windows; this harness answers the other question --
# what did the detectors fire on? -- deterministically. It runs one family script
# directly, waits for it to finish, waits two seconds for the service to catch up,
# and counts the hits the log recorded for that run.
#
# The count reads the tail of the log and keeps only lines whose timestamp is at
# or after the run started. Offsets were tried twice and both times the number
# was wrong: the service writes through a buffered logger, so bytes that belong
# to a run can still be in the buffer when the read begins -- measured on
# 2026-11-14, a matrix that counted by offset reported nothing for runs whose
# lines were in the file. A timestamp the logger wrote is the run's own clock and
# cannot be outrun.
#
# Two seconds of quiet after each script, because the detectors fire on events the
# service processes asynchronously.

$ErrorActionPreference = 'Continue'
$svc = 'C:\ProgramData\WenleAV\logs\service.log'
$ids = 'staged-and-run', 'document-spawned-script', 'persistence-arranged', 'mass-document-rename', 'ransomware-shape'
$corpus = 'C:\WenleAV\test\corpus'
$tail_bytes = 4 * 1024 * 1024

function Read-Tail {
    $file = Get-Item $svc
    $length = $file.Length
    $start = [Math]::Max(0, $length - $tail_bytes)
    $stream = [System.IO.File]::Open($svc, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $stream.Seek($start, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } finally {
        $stream.Dispose()
    }
}

function Count-Since([datetime]$since) {
    $counts = @{}
    foreach ($id in $ids) { $counts[$id] = 0 }
    $floor = $since.AddSeconds(-1)
    foreach ($line in (Read-Tail) -split "`n") {
        if ($line.Length -lt 19) { continue }
        try {
            # Cast rather than `TryParseExact`: PowerShell 5.1 cannot resolve
            # that overload with a `[ref]`, and the cast uses the current
            # culture, which is the culture the log was written in.
            $stamp = [datetime]::Parse($line.Substring(0, 19))
        } catch {
            continue
        }
        if ($stamp -lt $floor) { continue }
        foreach ($id in $ids) {
            if ($line.Contains("behaviour/$id")) { $counts[$id] += 1 }
        }
    }
    return $counts
}

$rows = New-Object System.Collections.Generic.List[string]
$rows.Add('kind,family,ran,seconds,' + ($ids -join ','))

$scripts = Get-ChildItem $corpus -Filter '*.ps1' | Sort-Object Name
foreach ($script in $scripts) {
    $kind = if ($script.BaseName -like 'malicious_*') { 'malicious' } elseif ($script.BaseName -like 'benign_*') { 'benign' } else { continue }
    $family = ($script.BaseName -replace '^(malicious|benign)_', '')
    $started = Get-Date
    $process = Start-Process -FilePath powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script.FullName
    )
    $finished = $process.WaitForExit(30000)
    $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
    Start-Sleep -Seconds 2
    $counts = Count-Since $started
    $cells = foreach ($id in $ids) { $counts[$id] }
    $rows.Add(('{0},{1},{2},{3},{4}' -f $kind, $family, [bool]$finished, $seconds, ($cells -join ',')))
    Write-Output ("{0,-22} ran={1} {2,6}s  {3}" -f $family, $finished, $seconds, ($cells -join ' '))
}

$out = Join-Path $corpus 'detector-matrix.csv'
$rows | Set-Content -Path $out -Encoding ASCII
Write-Output ("matrix written to {0}" -f $out)
