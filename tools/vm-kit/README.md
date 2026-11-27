# Collect attack behaviour in a guest with our own driver

The model has to learn behaviours as *this* driver reports them. Public capture
datasets are Sysmon logs from other machines and other attacks, and the measured
transfer was 0.2 %; the corpus this machine generates is fifteen scripted
families, which is not enough to speak about unknown threats. A guest is where
the missing data comes from: the same telemetry, a different set of techniques,
and no risk to the host.

## What the guest needs

- Windows 10 or 11, 64-bit, administrator.
- The product already installed in the guest: `WenleAvService` registered,
  `WenleAV\wenle-av-service.exe` present, the driver at
  `C:\WenleAV\driver\WenleAvFilter.sys` loadable.
- PowerShell 5.1 (the default).
- The `wenle-av` repository checkout inside the guest (this folder and
  `tools/behaviour-corpus.ps1` are what run).

If the product is not installed yet, copy the release folder into the guest and
install it there; the collection script refuses to start rather than produce a
log of nothing.

## What it runs

`tools/behaviour-corpus.ps1`'s families. They are simulations: they write files,
start processes, create and remove Run keys, tasks and services, read the SAM and
the credential store, list shadow copies, and put dangerous command lines on the
wire with `echo` rather than running them. No family encrypts anything, dumps a
credential, or touches another machine.

## Collect

```powershell
# In the guest, as administrator, from the repository root:
powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm-kit\collect.ps1 -Rounds 5
```

The script:

1. Checks the service and driver and refuses to continue if either is missing.
2. Starts the service and waits for the driver connection.
3. Runs every family in the corpus, `-Rounds` times, and records each window's
   start, end, family and pid in `labels.csv`.
4. Copies `behaviour.log`, `labels.csv` and `service.log` into
   `C:\WenleAV\vm-collection\` and zips them.

## Bring it back

Copy `C:\WenleAV\vm-collection\collection-<date>.zip` to the host and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\vm-kit\ingest.ps1 `
    -Zip C:\path\to\collection-2026-11-15.zip
```

`ingest.ps1` unpacks the zip under `target\vm-collections\`, checks the log has
the thirty-five-feature rows and the labels have windows, and prints what it
found. Training then reads the collection with the same `prepare_behaviour.py`
the host log uses.

## Why several rounds

A family's first run pays for cold caches and the shell's own start-up; the
second and later runs are the behaviour. Five rounds of every family is a few
minutes and gives the model both the shape and its variation. If a family needs
its own timing (a staged dropper wants the write and the start separated), the
corpus already waits.
