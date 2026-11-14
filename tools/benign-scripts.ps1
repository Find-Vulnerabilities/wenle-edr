# Ordinary script-host work: PowerShell and cmd doing what administrators and
# build tools do, with no malicious intent.
#
# The behaviour corpus is mostly PowerShell, and so is a dropper. A model trained
# on that corpus learns "PowerShell" and calls it a day: measured on 2026-11-14,
# the identity features took the training AUC to 1.000 and every held-out family
# to recall 1.0, which is not generalisation -- it is the same host on both
# sides. This workload is the negative sample that makes the question honest:
# after it, a model that still scores these high is firing on the script host
# rather than on the behaviour.

$ErrorActionPreference = 'SilentlyContinue'
$root = Join-Path $env:TEMP 'wenle-benign-scripts'
New-Item -ItemType Directory -Path $root -Force | Out-Null

# 1. Inventory: processes, services, hotfixes. The shape of a discovery script.
Get-Process | Select-Object -First 80 Id, ProcessName | Out-File (Join-Path $root 'processes.txt')
Get-Service | Select-Object -First 80 Name, Status | Out-File (Join-Path $root 'services.txt')
Get-HotFix | Select-Object -First 20 HotFixID | Out-File (Join-Path $root 'hotfixes.txt')

# 2. Registry reads: the keys an inventory script opens without writing.
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion' | Out-File (Join-Path $root 'windows.txt')
Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | Out-File (Join-Path $root 'run.txt')

# 3. File work: hash, copy, compare. The shape of a deployment or backup script.
$source = Join-Path $root 'source'
New-Item -ItemType Directory -Path $source -Force | Out-Null
1..40 | ForEach-Object { Set-Content -Path (Join-Path $source ("file{0:D2}.txt" -f $_)) -Value ('content ' * 60) }
Get-ChildItem $source | ForEach-Object { Get-FileHash $_.FullName | Out-File -Append (Join-Path $root 'hashes.txt') }
$copy = Join-Path $root 'copy'
Copy-Item $source $copy -Recurse -Force

# 4. Scheduled task inventory (read, not write), and a cmd shortcut.
schtasks /query /fo LIST 2>&1 | Out-File (Join-Path $root 'tasks.txt')
cmd /c "dir /s /b `"$copy`" > nul"

# 5. A child process chain that is ordinary: PowerShell starting cmd starting
#    another process, the shape a build script has.
powershell -NoProfile -Command "cmd /c echo ordinary" | Out-Null
cmd /c "powershell -NoProfile -Command `"Write-Output ordinary`"" | Out-Null

# 6. Compress and expand, which writes and renames many files at once.
$archive = Join-Path $root 'inventory.zip'
Compress-Archive -Path (Join-Path $root '*.txt') -DestinationPath $archive -Force
Expand-Archive -Path $archive -DestinationPath (Join-Path $root 'unpacked') -Force

Remove-Item $copy -Recurse -Force
Remove-Item (Join-Path $root 'unpacked') -Recurse -Force
Remove-Item $archive -Force

'benign script workload complete' | Add-Content (Join-Path $root 'done.txt')
