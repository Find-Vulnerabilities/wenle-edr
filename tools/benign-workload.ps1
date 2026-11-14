# A day of ordinary work, compressed: the benign shapes the behaviour model has
# to learn not to call malicious.
#
# Everything here is something a developer's machine does: a build writes object
# files and renames them, a package manager unpacks an archive, an editor writes
# a burst of small files, a compression tool reads and writes, a test runner
# starts and stops many short processes. None of it is malicious, and a model
# that fires on any of it is a model that a user turns off.
#
# The workload runs for a fixed number of rounds and stops. It is not a daemon:
# a script that quietly hammered a disk for ever would be the thing the product
# exists to stop.

$ErrorActionPreference = 'SilentlyContinue'
$root = Join-Path $env:TEMP 'wenle-benign-workload'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$repo = 'C:\Users\wensz\Downloads\wenle-av'
$rounds = 8

for ($round = 1; $round -le $rounds; $round++) {
    # 1. A build: the shape the model is most likely to overfit to, because it
    #    is the biggest burst of file writes a developer's machine produces.
    cmd /c "cd /d $repo && cargo build -p av-heuristics --release >nul 2>&1"

    # 2. Editor-style churn: many small files created, modified, renamed.
    $editor = Join-Path $root "editor-$round"
    New-Item -ItemType Directory -Path $editor -Force | Out-Null
    1..120 | ForEach-Object { Set-Content -Path (Join-Path $editor ("note{0:D3}.md" -f $_)) -Value ('# note ' * 20) }
    1..120 | ForEach-Object { Add-Content -Path (Join-Path $editor ("note{0:D3}.md" -f $_)) -Value ('more text ' * 10) }
    1..120 | ForEach-Object { Rename-Item -Path (Join-Path $editor ("note{0:D3}.md" -f $_)) -NewName ("note{0:D3}.bak" -f $_) }

    # 3. An archive: compresses its input and unpacks it again.
    $archive = Join-Path $root "archive-$round.zip"
    Compress-Archive -Path (Join-Path $editor '*.bak') -DestinationPath $archive -Force
    Expand-Archive -Path $archive -DestinationPath (Join-Path $root "unpacked-$round") -Force

    # 4. Many short processes, the shape of a test runner.
    1..30 | ForEach-Object { cmd /c "echo test $_ > nul" }

    # 5. A download to disk with no execution: what an installer's fetch looks
    #    like, and the shape a model could mistake for a stager.
    $payload = Join-Path $root "fetch-$round.bin"
    Set-Content -Path $payload -Value ('binary ' * 500)
    Move-Item -Path $payload -Destination (Join-Path $root "fetch-$round.tmp") -Force

    Remove-Item -Path $editor -Recurse -Force
    Remove-Item -Path $archive -Force
    Remove-Item -Path (Join-Path $root "unpacked-$round") -Recurse -Force
    Remove-Item -Path (Join-Path $root "fetch-$round.tmp") -Force
}

'benign workload complete' | Add-Content (Join-Path $root 'done.txt')
