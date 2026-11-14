# Measure each behaviour family against each detector, one at a time.
#
# The corpus runner records windows; this harness answers the other question --
# what did the detectors fire on? -- deterministically. It runs one family script
# directly, waits for it to finish, waits for the service to catch up, and counts
# the hits that appeared in the log *since the run started*.
#
# The count reads from the byte offset the log had before the run. The first
# version counted inside the last four thousand lines, and a busy minute pushed
# earlier hits out of that window: the matrix came back with negative counts,
# which is a measurement defect pretending to be a detector result.
#
# Why two seconds of quiet after each script: the detectors fire on events the
# service processes asynchronously, so a script's exit is not the end of its
# consequences. The wait is recorded in the output, so a slow run cannot hide.

$ErrorActionPreference = 'Continue'
$svc = 'C:\ProgramData\WenleAV\logs\service.log'
$ids = 'staged-and-run', 'document-spawned-script', 'persistence-arranged', 'mass-document-rename', 'ransomware-shape'
$corpus = 'C:\WenleAV\test\corpus'

function Read-Since([long]$offset) {
    $file = Get-Item $svc
    if ($file.Length -lt $offset) {
        # The log rotated during the run; everything it holds now is new.
        $offset = 0
    }
    $stream = [System.IO.File]::Open($svc, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $stream.Seek($offset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $reader = New-Object System.IO.StreamReader($stream)
        return $reader.ReadToEnd()
    } finally {
        $stream.Dispose()
    }
}

$rows = New-Object System.Collections.Generic.List[string]
$rows.Add('kind,family,ran,seconds,' + ($ids -join ','))

$scripts = Get-ChildItem $corpus -Filter '*.ps1' | Sort-Object Name
foreach ($script in $scripts) {
    $kind = if ($script.BaseName -like 'malicious_*') { 'malicious' } elseif ($script.BaseName -like 'benign_*') { 'benign' } else { continue }
    $family = ($script.BaseName -replace '^(malicious|benign)_', '')
    $offset = (Get-Item $svc).Length
    $started = Get-Date
    $process = Start-Process -FilePath powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script.FullName
    )
    $finished = $process.WaitForExit(30000)
    $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 2)
    Start-Sleep -Seconds 2
    $chunk = Read-Since $offset
    $cells = foreach ($id in $ids) {
        ([regex]::Matches($chunk, [regex]::Escape("behaviour/$id"))).Count
    }
    $rows.Add(('{0},{1},{2},{3},{4}' -f $kind, $family, [bool]$finished, $seconds, ($cells -join ',')))
    Write-Output ("{0,-22} ran={1} {2,6}s  {3}" -f $family, $finished, $seconds, ($cells -join ' '))
}

$out = Join-Path $corpus 'detector-matrix.csv'
$rows | Set-Content -Path $out -Encoding ASCII
Write-Output ("matrix written to {0}" -f $out)
