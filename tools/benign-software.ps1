# Drive real software the way a person does, so the benign side of the model is
# made of software rather than of the harness that measures it.
#
# The synthetic workloads (builds, hashing, copying) are useful hard negatives,
# but they are all the same shape: PowerShell starting PowerShell. A model
# calibrated on those learns that shape and then meets a browser, an installer
# and a package manager for the first time in production. This script runs the
# programs a developer's machine actually runs, each for long enough that its
# behaviour reaches the log.
#
# Nothing here changes the system in a way that needs undoing: package installs
# go into a temporary directory with `--no-save`, searches are local, and the
# one installer is fetched but only verified, not run.

$ErrorActionPreference = 'Continue'
$root = Join-Path $env:TEMP 'wenle-benign-software'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$log = Join-Path $root 'steps.log'

function Step([string]$name, [scriptblock]$body) {
    $started = Get-Date
    try {
        & $body *> (Join-Path $root "$name.out") 2>&1
        $code = $LASTEXITCODE
    } catch {
        $code = 'threw'
    }
    $seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    "$name,$code,$seconds" | Add-Content -Path $log
    Write-Output ("{0,-24} exit={1} {2}s" -f $name, $code, $seconds)
}

# Browsers: a headless render is the same code path as a window, without taking
# the screen.
Step 'chrome-headless' {
    $chrome = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
    if (Test-Path $chrome) {
        & $chrome --headless --disable-gpu --dump-dom 'data:text/html,<h1>wenle</h1>' 2>$null | Out-Null
        & $chrome --headless --disable-gpu --screenshot="$root\shot.png" 'data:text/html,<h1>shot</h1>' 2>$null | Out-Null
    }
}

# A package manager doing a real resolve and download.
Step 'npm-install' {
    $project = Join-Path $root 'npm'
    New-Item -ItemType Directory -Path $project -Force | Out-Null
    Push-Location $project
    '{ "name": "benign", "version": "1.0.0" }' | Set-Content package.json
    & npm install --no-audit --no-fund left-pad 2>$null | Out-Null
    Pop-Location
}

Step 'pip-download' {
    & python -m pip download --no-deps --dest (Join-Path $root 'pip') requests 2>$null | Out-Null
}

Step 'git-clone' {
    & git clone --depth 1 https://github.com/octocat/Hello-World.git (Join-Path $root 'git') 2>$null | Out-Null
}

Step 'sevenzip' {
    $archive = Join-Path $root 'many.zip'
    $folder = Join-Path $root 'many'
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    1..40 | ForEach-Object { Set-Content -Path (Join-Path $folder ("f{0:D2}.txt" -f $_)) -Value ('x' * 2000) }
    Compress-Archive -Path (Join-Path $folder '*') -DestinationPath $archive -Force
    Expand-Archive -Path $archive -DestinationPath (Join-Path $root 'many-out') -Force
}

Step 'defender-scan' {
    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
}

Step 'winget-list' {
    & winget list 2>$null | Out-Null
}

Step 'update-scan' {
    & UsoClient StartScan 2>$null | Out-Null
}

Step 'notepad-calc' {
    Start-Process notepad.exe -PassThru | ForEach-Object { Start-Sleep -Seconds 2; Stop-Process -Id $_.Id -Force }
    Start-Process calc.exe -PassThru | ForEach-Object { Start-Sleep -Seconds 2; Stop-Process -Id $_.Id -Force }
}

Step 'office-probe' {
    if (Test-Path 'C:\Program Files\Microsoft Office') {
        Get-ChildItem 'C:\Program Files\Microsoft Office' -Recurse -Filter 'WINWORD.EXE' -ErrorAction SilentlyContinue |
            Select-Object -First 1 | ForEach-Object { Start-Process $_.FullName -PassThru | ForEach-Object { Start-Sleep -Seconds 5; Stop-Process -Id $_.Id -Force } }
    }
}

"steps written to $log" | Out-Null
