# Wenle EDR

An endpoint agent for Windows, written in Rust. A kernel minifilter sees file
operations before they happen, the service decides about them, and a behaviour
engine watches what processes do and can stop one while it is running.

There is no cloud, no telemetry, no machine learning and no feed. Everything it
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

Two ways to give it rules:

- **Your own.** `wenle build <file.yar>` compiles YARA sources (`.yar`, `.yara`)
  or this product's `.avrule` syntax into the database the engine reads.
  `wenle build --report` says which constructs were refused and why.
- **YARA-Forge.** `tools/fetch-rules.ps1` downloads the tier you choose (core,
  extended or full), compiles it, and puts the database where the service expects
  it. Run it elevated, once, after installing.

Without a database the engine still starts and finds nothing; `wenle service
status` says so rather than calling every file clean.

## Behaviour

68 rules over file, registry and process events. Each one scores below the
malicious threshold on its own â€” that is deliberate, because a single rule is
one fact and a fact is not a verdict. When several rules name the same process
inside sixty seconds, the engine adds their scores; at 100, and with at least
one contributor that is evidence about what the process did rather than how much
of it, it produces one finding with a termination behind it.

Measured with a real WannaCry sample on 2026-11-06, in a guest, with the sample
directory excluded from scanning so that nothing but behaviour could catch it: a
`.WNCRY` rename, a burst of deletes and a burst of writes scored 150 together,
and the process was stopped in the same second the first of them arrived.

## What it costs

Measured on the test machines: a 16 GB Windows 11 host and a Windows 11 guest,
driver loaded, Defender real-time switched off. Two memory numbers are given
because they are two different facts, and a working set that Windows has trimmed
and a process that allocated less look identical in Task Manager.

| | |
|---|---|
| idle working set, after Windows trims it | 80â€“150 MB |
| private bytes while idle | 330–420 MB |
| CPU, ordinary use | 1â€“5 % of one core |
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

## What it does not do

It does not have a feed. It does not watch raw disk writes, so a
bootkit's partition-table write is invisible to it. It is English only, and the
window is a plain egui application.

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

## Updates

`wenle update` verifies a package against a `sha256` manifest before touching
anything, stops the service, replaces the files and starts it again. The order
the steps happen in is a Lua script; the file operations are Rust, and the script
cannot name a path. `wenle update rollback` puts back what the last update
replaced, and `wenle update fetch` builds a package from a release manifest over
HTTPS.

## Licensing

The code is MIT (`LICENSE`).

No rules are distributed with it, so none is covered by that grant. `wenle build`
compiles rule sources you supply. `tools/fetch-rules.ps1` downloads
[YARA-Forge](https://github.com/YARAHQ/yara-forge) on your machine; its
packaging tool is GPL-3.0 and the rules it collects come from forty-odd upstream
repositories, each keeping its own licence — not uniform, and some state none.
That script is a convenience for the person running it, not a redistribution by
this project: whatever you compile from it is yours to keep and not to hand on.
