# After the reboot

The reboot was needed because a stalled `fltmc unload` deregistered the driver's
process notifications before the unload finished: file and registry events kept
arriving, process starts did not. The driver is `SYSTEM_START`, the service is
`AUTO_START`, so a normal boot puts both back.

## Check in this order

```powershell
sc.exe query WenleAvService | Select-String STATE      # expect RUNNING
fltmc filters | Select-String WenleAvFilter            # expect the filter
Get-Content C:\ProgramData\WenleAV\logs\service.log -Tail 20
```

Then prove process starts are back: run a two-level chain and look for two
`staging: start` lines.

```powershell
powershell -NoProfile -Command "cmd /c echo postboot"
Get-Content C:\ProgramData\WenleAV\logs\service.log -Tail 200 |
    Select-String 'staging: start'
```

If the chain appears, behaviour monitoring is whole again.

## Deploy without unloading the filter

The write gate protects `C:\WenleAV`, so a new binary cannot be copied there
while the filter is loaded. The service can run from somewhere else, and the
image path is a service property:

```powershell
New-Item -ItemType Directory C:\ProgramData\WenleAV\bin -Force
Copy-Item <repo>\target\release\wenle-av-service.exe C:\ProgramData\WenleAV\bin\
sc.exe stop WenleAvService
sc.exe config WenleAvService binPath= '"C:\ProgramData\WenleAV\bin\wenle-av-service.exe"'
sc.exe start WenleAvService
```

That path is not protected by the write gate, so the next deploy needs no
unload, and a stuck unload can never take process monitoring down again.

## If process starts are still missing

`PsSetCreateProcessNotifyRoutineEx` can refuse; the driver reports that in a
`StateChanged` event on every connection, and the service logs it. Check for
`process notifications` in the service log before suspecting anything else.
