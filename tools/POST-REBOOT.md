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

## If process starts stop again after a while

Measured on 2026-11-15, after the reboot and a clean reload: a few process
starts arrive (the shell, its child), then none at all, while file events keep
flowing. The driver bounds queued process events at sixty-four
(`MAX_PENDING_PROCESS_EVENTS`) and drops anything beyond that. Each send waits up
to five seconds on `FltSendMessage`, and the service reads the port on the same
thread that scans files, so a burst of starts during a scan can fill the queue:
sixty-four drops, and then every later process event is dropped too. The counter
is decremented by the worker, so this is a stall rather than a leak.

What to do about it, in order of cost:

1. Reload the filter (`fltmc unload` / `fltmc load`, with the service stopped)
   resets the queue; that is what made the next few starts appear again.
2. Service: drain driver events on a thread that never scans, and hand scans to a
   worker; the reader must not wait for a verdict.
3. Driver: raise the bound and give the send a short timeout so a slow reader
   loses one event rather than all of them.
