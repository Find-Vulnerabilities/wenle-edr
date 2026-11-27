# Wenle EDR

An EDR with AI: a behaviour model scores every process story, the rules
argue from evidence, and the agent decides in the open.

An endpoint agent for Windows, written in Rust. A kernel minifilter sees file
operations before they happen, the service decides about them, and a behaviour
engine watches what processes do and can stop one while it is running.

There is no cloud, no telemetry and no feed. The behaviour model is
compiled into the binary and its weights ship with the service. Everything it
knows is compiled into the binary, and every verdict names the evidence behind
it.

## Interception

The driver sits at altitude 321000. It can refuse five things:

- a write to one of the product's own files;
- a delete of one;
- a rename of one, in either direction;
- an open that would truncate one;
- an executable section, which is the only way a program is stopped before it
  runs. The filter manager honours exactly one status there,
  `STATUS_INSUFFICIENT_RESOURCES`, and that is what a conviction returns.

Everything else is reported and allowed. A gate that guesses is worse than a
gate that says nothing.

## Rules are not included

The product ships no static rules. Rules are other people's work under other
people's licences, and this repository distributes code only.

`wenle rules update` fetches the newest YARA-Forge extended package, checks it
against the SHA-256 GitHub publishes for that release asset, compiles it with the
same compiler `wenle build` uses, and installs the result where the service reads
it. The previous database is kept as `rules.avdb.before-feed`. `wenle rules
status` shows what is installed, what is published, and whether the database on
disk still matches the digest recorded when it was installed. `wenle rules auto
on` lets the service keep it current once a week.

The digest is the release's own, not one this program computes: a hash of a
download that could have been replaced proves nothing, and GitHub's asset digest
is the one reference the download cannot change.

Without a database the engine still starts and finds nothing; `wenle service
status` says so rather than calling every file clean.
## Detection

### The three models

**PE model.** A LightGBM forest over 2,091 features of the file's shape: section
layout, entropy, imports, resources, overlay and byte histogram. It runs when
the rules convict nothing and nothing proves the file good. The conviction band
is 0.1716 and the reporting band 0.0916, both measured on family-held-out
splits; above the conviction band the model found 90.8% of unseen families at a
0.1% false-positive rate. Programs with a valid signature are discounted before
the band is applied.

**Script model.** One model for every language, not one per language, and it
decodes before it looks: BOM, UTF-8, UTF-16 and the local code page are read to
text, so the same script in two encodings is one sample. Each language's
spelling of an operation is replaced with one token (`iex`, `eval`,
`WScript.Shell.Run` and `exec(` all become `<exec>`), and the text is hashed
into character n-grams. 800 trees, 27 dense columns and the hashed grams.
Conviction is 0.7979, the 1% false-positive point measured on 4,000 real
JavaScript files and 2,848 machine scripts. Held-out languages at a 1% false
positive rate: batch, JavaScript, VBScript and HTA 100%; Python 53% when the
whole language is excluded, which is stated rather than hidden.

**Behaviour story model.** The events one process produced, the last 64 of them,
47 numbers each, scored by 500 trees. At a 0.1% per-sequence false-positive rate
it caught 46 of 50 technique families (92%), and 48 of 50 at 1%. Its stop
authority is on by default, and every stop goes through a guard that refuses
protected image names (`csrss`, `lsass`, `services`, `svchost`, `explorer` and
the rest), anything under `C:\Windows`, session-0 services and an unknown image.
A story model cannot take the machine down with the process, which is what the
first version of this did; the blue screen is recorded in `docs/`.

### Behaviour rules

68 rules over file, registry and process events. Each one scores below the
malicious threshold on its own — that is deliberate, because a single rule is
one fact and a fact is not a verdict. When several rules name the same process
inside sixty seconds, the engine adds their scores; at 100, and with at least
one contributor that is evidence about what the process did rather than how much
of it, it produces one finding with a termination behind it.

Measured with a real WannaCry sample on 2026-11-06, in a guest, with the sample
directory excluded from scanning so that nothing but behaviour could catch it: a
`.WNCRY` rename, a burst of deletes and a burst of writes scored 150 together,
and the process was stopped in the same second the first of them arrived.

### Memory

The service walks a process's regions and reads the private ones that are both
readable and executable. Two things produce findings: a signature match, and a
writable-and-executable page with no file behind it. The second is the shape of
injected code and also of a just-in-time compiler, so it is reported, not
convicted; a thread that begins *inside* the page is what convicts, and the
process is stopped. A trusted signature on the image, an image under
`C:\Windows` or Program Files, a page that holds a PE, or a process holding far
more such pages than hand-written code does each keep the finding at report
only. The same guard as every other stop decides whether the process may be
stopped at all.

### Archives

Packages are opened and every member is judged by the same engine, both models
included. A finding names the chain of member names it was found under, so a
report says which file inside which folder was convicted.

### AMSI

The provider examines the text a script host is about to run, after the host has
de-obfuscated it. The buffer is named as a script so the script model applies to
it, and a conviction is what the provider answers back; a `Suspicious` verdict is
reported and not blocked, because the product's middle band warns and never acts.

## The sandbox

The service does not wait for an emulation: its decisions have a 250 ms
deadline. A scan that lands in the suspicious band writes a job file into
`%ProgramData%\WenleAV\sandbox\queue\` and returns at once. The
`WenleSandboxWorker` task (at startup and every five minutes, as SYSTEM) runs:

```
sandbox\bin\wenle-mwemu.exe --once
```

That is a native Rust worker. It starts the patched `mwemu.exe` engine under
`sandbox\mwemu\bin\`, reads the engine's event JSON and trace, follows child
processes, and writes `sandbox\results\<sha256>.json`. The next scan of those
bytes reads that file before the verdict is computed. There is no Python, venv,
PowerShell or `update.lua` in this path.

What the run adds:

* **a virtual clock.** Sleeps and waits return between instructions while the
  clock moves forward; the engine's `GetTickCount`, `GetTickCount64`,
  `timeGetTime` and `QueryPerformanceCounter` read the same clock. A sample that
  sleeps and measures sees the time it asked for.
* **a plausible machine.** The patched engine receives a Windows version, user,
  host name, domain, endpoint, registry file, maps and `file_root` from
  `engine.json`, so process, path and network behaviour has a stable environment
  to run in.
* **the unpacked code.** The worker parses regions the engine reports written
  and then executed, and scans them with this product's own engine, which is
  where a packed payload meets the PE model.
* **the decisive behaviours.** A ransomware shape (`vssadmin`, `wbadmin`,
  `bcdedit`), a credential tool, an event-log clear, or a dropped driver that is
  started is `sandbox/decisive` and takes the quarantine path. A convicted
  unpacked region is `sandbox/unpacked`. Other families are reported at Low.

The sample is never executed on the host; the emulator reads it. Script
detection stays with the script heuristics, the external JS policy, the script
model and AMSI; the native engine is used for PE behaviour, not as a script
host. The engine, maps, registry and `file_root` are native data under
`sandbox\mwemu`; updating them does not require Python or a wheel venv.

## Updates and releases

The code is MIT. The current release is 1.0.0, built from the `main` tree it is
attached to. It has the `wenle-1.0.0.zip` plus the same files loose: the
products, `manifest.txt`, `install-wenle.ps1`, `js-policy.json`, the driver and
its test certificate. `wenle update fetch <manifest URL>` uses the loose
manifest and downloads the files it names from the same release. Older
releases were removed; 1.0.0 is the first supported build.

`wenle update fetch <manifest URL>` downloads the files a release manifest names
over HTTPS and checks each against its SHA-256. `wenle update verify <dir>`
checks a local package and changes nothing. `wenle update apply <dir>` verifies,
stops the service, installs the files its manifest names (and nothing else), and
starts it again. The order is the built-in flow compiled into `wenle.exe`;
there is no user-supplied Lua script and no `update.lua` in a package. The
updater still verifies every file against `manifest.txt` before and during the
copy. `wenle update rollback`
puts back the files the last update replaced. A service stuck in `STOP_PENDING`
is terminated and waited for rather than reported as an error, because the SCM
refuses every further control in that state.

## Installing a clean machine

Every release carries both the zip and the loose files from it, including
`install-wenle.ps1`, the executables, `av_amsi.dll` and `manifest.txt`.
`install-wenle.ps1` is the supported bootstrap for a machine that
has no Wenle service or driver yet; `wenle update apply` is only for a machine
that already runs a previous release. Extract the zip and run the installer
from it.

On a clean Windows machine, from an elevated PowerShell:

```powershell
Expand-Archive .\wenle-1.0.0.zip C:\WenleInstall
cd C:\WenleInstall
.\install-wenle.ps1 -DryRun
.\install-wenle.ps1
```

The first run validates the payload, trusts `wenle-test-2026.cer`, enables test
signing, registers a highest-privilege AtLogOn resume task, and reboots. After
sign-in the task runs `-Resume` automatically: it copies the payload to
`C:\WenleAV`, installs the service and driver, fetches rules when the payload
does not carry `rules.avdb`, registers the integrations, takes the integrity
manifest, verifies, and starts the GUI. If the driver is not loaded yet it
requests one more reboot. State and log are under `%ProgramData%\WenleAV`; the
task removes itself when the install completes.

The driver is test-signed. Secure Boot must be off, test signing must be on,
and HVCI may refuse the driver; this is not a production installer. The 1.0.0
kernel package does not include `av_amsi.dll`; AMSI is skipped unless the DLL
is placed beside the installer and `-EnableAmsi` is passed.

## What it costs

Measured on the test machines: a 16 GB Windows 11 host and a Windows 11 guest,
driver loaded, Defender real-time switched off. Two memory numbers are given
because they are two different facts, and a working set that Windows has trimmed
and a process that allocated less look identical in Task Manager.

| | |
|---|---|
| working set in ordinary use, measured after scans and before Windows trims it | about 250 MB (251–300 MB on the test host) |
| idle working set, after Windows trims it | 80–150 MB |
| private bytes while running | 450–500 MB |
| CPU, ordinary use | 1–5 % of one core |
| CPU, scanning bursts | up to two cores |
| the first minutes after boot | up to 1.3 GB working set while the scan queue drains, trimmed back by Windows |
| one 5 MB DLL through the section gate | 3.5 s and often longer; the driver stops waiting and allows the section |


What moves these numbers: how many directories are watched (five on the guest,
twenty on the host), whether a scan is running, and how much the OS keeps
resident.

A 120-minute soak in the guest under file, process and registry load, 110
samples: private bytes +19.6 KB/hour (from 292,576 KB to 292,616 KB), handles
-0.04/hour, nonpaged pool +523 KB/hour, and no bugcheck. The instability
thresholds the run uses are 1024 KB/hour and one handle per hour, so it passes by
a wide margin, and the nonpaged slope is the one to keep an eye on.

## Build

```
cargo build --release                  # wenle.exe, wenle-av-service.exe, wenle-gui.exe, av_amsi.dll
cd crates/av-driver && cargo build     # the minifilter; needs the WDK and its own toolchain
```

The user-mode programs are built together; the AMSI provider is a separate
`cdylib`. No rule database is included; see Rules are not included above for the
two ways to produce one.

The driver is signed with a test certificate, so Windows loads it only with
`bcdedit /set testsigning on` and a reboot.

## What it changes on the machine

Every command below needs administrator rights and is undone by the command
next to it. Nothing else writes outside `%ProgramData%\WenleAV`.

| Command | What it writes | Undone by |
|---|---|---|
| `wenle service install` | One service, starting at boot. | `wenle service remove` |
| `wenle integrate driver install` | `System32\drivers\WenleAvFilter.sys` and its filter service key. | `wenle integrate driver remove` |
| `wenle integrate amsi install` | The AMSI provider keys for `av_amsi.dll`. | `wenle integrate amsi remove` |
| `wenle integrate shell install --machine` | Four Explorer verbs under `HKLM\SOFTWARE\Classes`. | `wenle integrate shell remove --machine` |
| `wenle integrate defender disable` | **Turns off Defender's real-time protection.** The previous value is recorded first. | `wenle integrate defender restore` |
| `wenle protect apply` | The DACLs of the product's own directories, recorded first. | `wenle protect restore` |

`wenle protect status` reports all of it without changing anything.

## Protecting the product itself

The service is configured so that an ordinary process cannot disable it: its
security descriptor allows control only to SYSTEM and Administrators, its start
type is automatic, and the SCM restarts it five and ten seconds after a failure.
`wenle protect manifest` records the digest of every installed file and
`wenle protect verify` compares against that record, so a replaced binary is
visible even when everything still runs.

These are user-mode measures. A process running as an administrator can still
terminate the service; the service comes back, but it does come back rather than
refuse to die. Kernel-level refusal needs an object callback that strips
`PROCESS_TERMINATE` from handles opened against the product, which is a driver
change requiring test signing and a VM to develop against, and it is not in this
build.

## Licensing

The code is MIT (`LICENSE`).

No rules are distributed with it, so none is covered by that grant. `wenle build`
compiles rule sources you supply. `tools/fetch-rules.ps1` downloads
[YARA-Forge](https://github.com/YARAHQ/yara-forge) on your machine; its
packaging tool is GPL-3.0 and the rules it collects come from forty-odd upstream
repositories, each keeping its own licence � not uniform, and some state none.
That script is a convenience for the person running it, not a redistribution by
this project: whatever you compile from it is yours to keep and not to hand on.

