<#
.SYNOPSIS
    Run the samples the service queued for the sandbox.

.DESCRIPTION
    The service cannot wait for an emulation: its decisions have a 250 ms
    deadline. So a scan that lands in the suspicious band writes a small job
    file into `sandbox\queue\` and returns. This script is the other half:

      1. takes up to five jobs from the queue,
      2. runs `sandbox_run.py` in the sandbox's own Python environment against
         the sample, with the virtual clock and the plausible-machine config,
      3. writes the run's `summary.json` to `sandbox\results\<sha256>.json`,
         which is the file the next scan of those bytes reads,
      4. moves the job to `done\` (or to `failed\` with the log line).

    It is registered as the scheduled task `WenleSandboxWorker`, every five
    minutes and at startup, running as SYSTEM. A missing sample, a corrupt
    summary or an emulator crash is recorded and the job is not retried for ever.

.PARAMETER SandboxDir
    The sandbox's state directory. Default: %ProgramData%\WenleAV\sandbox.
#>
[CmdletBinding()]
param(
    [string] $SandboxDir = "$env:ProgramData\WenleAV\sandbox",
    [int] $MaxJobs = 5
)

$ErrorActionPreference = 'Continue'

function Write-Log([string] $Message) {
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path (Join-Path $SandboxDir 'worker.log') -Value $line
}

$python = Join-Path $SandboxDir 'venv\Scripts\python.exe'
$runner = Join-Path $SandboxDir 'sandbox_run.py'
$queue = Join-Path $SandboxDir 'queue'
$results = Join-Path $SandboxDir 'results'
$done = Join-Path $SandboxDir 'done'
$failed = Join-Path $SandboxDir 'failed'

if (-not (Test-Path $python) -or -not (Test-Path $runner)) {
    Write-Log "worker: no sandbox at $SandboxDir (python or runner missing); nothing to do"
    exit 0
}
New-Item -ItemType Directory -Path $queue, $results, $done, $failed -Force | Out-Null

$jobs = Get-ChildItem $queue -Filter '*.job' -ErrorAction SilentlyContinue | Select-Object -First $MaxJobs
if (-not $jobs) {
    exit 0
}

foreach ($job in $jobs) {
    $sha = $job.BaseName
    $lines = Get-Content $job.FullName -ErrorAction SilentlyContinue
    if (-not $lines -or $lines.Count -lt 1) {
        Move-Item $job.FullName (Join-Path $failed $job.Name) -Force
        Write-Log "worker: $sha had no sample path; moved to failed"
        continue
    }
    $sample = $lines[0].Trim()
    if (-not (Test-Path $sample)) {
        Move-Item $job.FullName (Join-Path $failed $job.Name) -Force
        Write-Log "worker: $sha sample is gone ($sample); moved to failed"
        continue
    }

    $out = Join-Path $results ("run-" + $sha)
    New-Item -ItemType Directory -Path $out -Force | Out-Null
    Write-Log "worker: running $sha ($sample)"
    & $python $runner --sample $sample --out $out --seconds 60 2>&1 | Select-Object -Last 3 | ForEach-Object { Write-Log ("worker: " + $_) }
    $summary = Join-Path $out 'summary.json'
    if (Test-Path $summary) {
        Copy-Item $summary (Join-Path $results ($sha + '.json')) -Force
        Move-Item $job.FullName (Join-Path $done $job.Name) -Force
        Write-Log "worker: $sha finished, summary cached"
    } else {
        Move-Item $job.FullName (Join-Path $failed $job.Name) -Force
        Write-Log "worker: $sha produced no summary; moved to failed"
    }
}
