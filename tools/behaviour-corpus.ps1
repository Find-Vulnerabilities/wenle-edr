# Behaviour corpus: harmless scripts that exercise the shapes a behaviour model
# has to learn, run one at a time with the window recorded.
#
# Every family here is harmless by construction: files are written under %TEMP%
# and removed, registry values are written and deleted, scheduled tasks and
# services are created and deleted, and nothing touches a file outside its own
# folder. The point is the *shape* of the events -- a drop burst, a Run key, a
# shadow-copy command line -- not the effect.
#
# Each family is written as its own script so the event log carries a process
# boundary, and the runner records start/end microsecond timestamps beside the
# label. The trainer labels a sequence by the window it falls in; a family that
# ran while a build was also running is labelled by the tighter window, which is
# why the windows are written out rather than inferred.

$ErrorActionPreference = 'SilentlyContinue'
$root = 'C:\WenleAV\test\corpus'
$labels = 'C:\WenleAV\test\corpus\labels.csv'
New-Item -ItemType Directory -Path $root -Force | Out-Null

function Write-Family([string]$name, [string]$body) {
    $path = Join-Path $root ("$name.ps1")
    # ASCII: the generated scripts are commands, and a non-ASCII character in a
    # script that is executed by a hidden host is an encoding argument nobody
    # needs.
    [System.IO.File]::WriteAllText($path, $body, (New-Object System.Text.ASCIIEncoding))
    return $path
}

$families = @{}

$families['dropper'] = @'
$root = Join-Path $env:TEMP 'corpus-dropper'
New-Item -ItemType Directory -Path $root -Force | Out-Null
1..40 | ForEach-Object { Set-Content -Path (Join-Path $root ("stage{0:D2}.dat" -f $_)) -Value ('enc ' * 200) }
Start-Process -FilePath cmd.exe -ArgumentList '/c', 'echo child > nul' -WindowStyle Hidden
Start-Sleep -Milliseconds 300
Remove-Item -Path $root -Recurse -Force
'@

$families['ransomware_stager'] = @'
$root = Join-Path $env:TEMP 'corpus-ransom'
New-Item -ItemType Directory -Path $root -Force | Out-Null
1..20 | ForEach-Object { Set-Content -Path (Join-Path $root ("doc{0:D2}.txt" -f $_)) -Value 'document' }
Start-Sleep -Milliseconds 200
1..20 | ForEach-Object { Rename-Item -Path (Join-Path $root ("doc{0:D2}.txt" -f $_)) -NewName ("doc{0:D2}.locked" -f $_) }
Remove-Item -Path $root -Recurse -Force
'@

$families['persistence_run'] = @'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Set-ItemProperty -Path $key -Name 'CorpusUpdater' -Value 'C:\Windows\System32\cmd.exe /c echo x'
Start-Sleep -Milliseconds 300
Remove-ItemProperty -Path $key -Name 'CorpusUpdater'
'@

$families['persistence_task'] = @'
schtasks /create /tn CorpusTask /tr "cmd.exe /c echo x" /sc minute /mo 5 /f | Out-Null
Start-Sleep -Milliseconds 500
schtasks /delete /tn CorpusTask /f | Out-Null
'@

$families['credential_access'] = @'
$strings = @('sekurlsa::logonpasswords','lsadump::sam','privilege::debug','Invoke-Mimikatz')
$strings | ForEach-Object { Write-Output $_ }
Get-Process -Name lsass | Select-Object -First 1 | Out-Null
'@

$families['lolbin_chain'] = @'
cmd.exe /c "powershell -NoProfile -Command \"cmd /c echo chain\"" | Out-Null
Start-Sleep -Milliseconds 400
rundll32.exe shell32.dll,Control_RunDLL | Out-Null
'@

$families['obfuscated_ps'] = @'
$b = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes('Write-Output harmless'))
$c = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($b))
Invoke-Expression $c
'@

$families['download_cradle'] = @'
$cradle = 'IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1:9/none.ps1")'
Write-Output $cradle
'@

$families['infostealer_sim'] = @'
$profiles = @(
  (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'),
  (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Login Data')
)
$target = Join-Path $env:TEMP 'corpus-steal'
New-Item -ItemType Directory -Path $target -Force | Out-Null
foreach ($p in $profiles) { if (Test-Path $p) { Copy-Item $p (Join-Path $target 'stolen.db') -Force } }
Start-Sleep -Milliseconds 400
Remove-Item $target -Recurse -Force
'@

$families['lateral_sim'] = @'
net view 2>&1 | Out-Null
net use 2>&1 | Out-Null
Start-Sleep -Milliseconds 300
'@

$families['defence_evasion'] = @'
$commands = @(
  'vssadmin delete shadows /all /quiet',
  'bcdedit /set {default} recoveryenabled No',
  'wbadmin delete catalog -quiet'
)
$commands | ForEach-Object { Write-Output $_ }
'@

$families['service_install'] = @'
sc.exe create CorpusService binPath= "cmd.exe /c echo x" start= demand | Out-Null
Start-Sleep -Milliseconds 400
sc.exe delete CorpusService | Out-Null
'@

# The benign workloads the model must not call malicious. They are recorded with
# the same fields so the trainer sees them beside the families.
$benign = @{
    'benign_build' = @'
cmd /c "cd /d C:\Users\wensz\Downloads\wenle-av && cargo build -p av-heuristics --release >nul 2>&1"
'@
    'benign_files' = @'
$root = Join-Path $env:TEMP 'corpus-benign'
New-Item -ItemType Directory -Path $root -Force | Out-Null
1..60 | ForEach-Object { Set-Content -Path (Join-Path $root ("note{0:D2}.txt" -f $_)) -Value ('text ' * 100) }
Start-Sleep -Milliseconds 300
Remove-Item -Path $root -Recurse -Force
'@
    'benign_installer' = @'
cmd /c "winget --version" | Out-Null
Start-Sleep -Milliseconds 300
'@
}

$rows = New-Object System.Collections.Generic.List[string]
# Appended, not overwritten: every round is another window for the trainer, and
# a second run that replaced the first would throw away the first day of data.
if (-not (Test-Path $labels)) {
    $rows.Add('start_micros,end_micros,label,family,pid')
}

function Invoke-One([string]$label, [string]$family, [string]$body) {
    $path = Write-Family -name ("{0}_{1}" -f $label, $family) -body $body
    $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000
    # Run in a fresh host so the story begins at the script, and wait for it:
    # a window that overlapped the next family would be labelled twice. The pid
    # is recorded because a window is not a label: a build running beside the
    # corpus is inside the same window and is not malicious, and measured on
    # 2026-11-14 a time-only label called 37,929 sequences malicious when the
    # families were a few hundred.
    $process = Start-Process -FilePath powershell.exe -WindowStyle Hidden -PassThru -Wait -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $path
    )
    $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000
    $pid_text = if ($process) { $process.Id } else { 0 }
    $rows.Add(("{0},{1},{2},{3},{4}" -f $start, $end, $label, $family, $pid_text))
    Write-Output ("{0} {1} {2} us" -f $label, $family, ($end - $start))
}

foreach ($name in $families.Keys) { Invoke-One 'malicious' $name $families[$name] }
foreach ($name in $benign.Keys) { Invoke-One 'benign' $name $benign[$name] }

Add-Content -Path $labels -Value $rows -Encoding ASCII
Write-Output ("labels: {0} windows, written to {1}" -f ($rows.Count - 1), $labels)
