#!/usr/bin/env python3
"""Turn Sysmon event logs into the feature space the service serves.

The behaviour model reads thirty-five numbers per event, computed by
`av_behaviour::Features`. Public attack datasets are Sysmon logs, which are a
different shape: an EventID, a path, a command line. This converts one into the
other using the same rules as `crates/av-behaviour/src/sequence.rs`:

    0..10   action one-hot (11)
    11..17  path class (7)
    18..23  extension class (6)
    24..27  registry class (4)
    28..31  command-line flags (4)
    32      log-scaled gap
    33,34   image and parent class

The conversion is the contract: a model trained on converted Sysmon and served
on our telemetry is only meaningful if both sides agree about what "temp" means
and what `powershell.exe` is. The constants below are copied from the Rust and
are asserted against the same numbers in the tests of that file.

Usage:
    python tools/sysmon_to_features.py --input <events.json> --out <file.npz>
"""

import argparse
import json
import sys

import numpy as np

WIDTH = 35
LENGTH = 64
TICKS_PER_SECOND = 10_000_000  # the DSL's clock; used only for the gap feature

ACTIONS = {
    "ExecutionBlocked": 0,
    "FileWritten": 1,
    "ImageLoaded": 2,
    "ProcessStarted": 3,
    "WriteBlocked": 4,
    "Heartbeat": 5,
    "StateChanged": 6,
    "EventsDropped": 7,
    "FileRenamed": 8,
    "FileDeleted": 9,
    "RegistryChanged": 10,
}


def path_class(path):
    if not path:
        return 6
    lower = path.lower()
    if "\\temp\\" in lower or "\\tmp\\" in lower or lower.endswith("\\temp"):
        return 0
    if "\\appdata\\" in lower:
        return 1
    if "\\startup\\" in lower:
        return 2
    if "\\windows\\system32" in lower or "\\windows\\syswow64" in lower:
        return 3
    if "\\program files" in lower or "\\programdata\\" in lower:
        return 4
    if lower.startswith("\\\\"):
        return 5
    return 6


def extension_class(path):
    if not path:
        return 5
    lower = path.lower()
    extension = lower.rsplit(".", 1)[-1] if "." in lower else ""
    if extension in ("exe", "dll", "sys", "scr", "cpl"):
        return 0
    if extension in ("ps1", "psm1", "vbs", "vbe", "js", "jse", "bat", "cmd", "hta"):
        return 1
    if extension in ("doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "pdf"):
        return 2
    if extension in ("zip", "rar", "7z", "cab", "msi"):
        return 3
    if extension in ("tmp", "dat", "log", "txt"):
        return 4
    return 5


def registry_class(path):
    if not path:
        return 3
    lower = path.lower()
    if "currentversion\\run" in lower:
        return 0
    if "\\services\\" in lower or "currentcontrolset\\services" in lower:
        return 1
    if lower.startswith("hkey") or lower.startswith("hkcu") or lower.startswith("hklm"):
        return 2
    return 3


def flags(command_line):
    if not command_line:
        return [0.0, 0.0, 0.0, 0.0]
    squashed = "".join(command_line.lower().split())
    return [
        float("-windowstylehidden" in squashed or "-whidden" in squashed),
        float("-enc" in squashed or "-encodedcommand" in squashed),
        float(
            "downloadstring" in squashed
            or "downloadfile" in squashed
            or "net.webclient" in squashed
            or "invoke-webrequest" in squashed
        ),
        float("iex(" in squashed or "invoke-expression" in squashed),
    ]


def image_class(path):
    if not path:
        return 8
    name = path.lower().rsplit("\\", 1)[-1]
    if name in ("powershell.exe", "pwsh.exe"):
        return 0
    if name == "cmd.exe":
        return 1
    if name in ("wscript.exe", "cscript.exe", "mshta.exe"):
        return 2
    if name in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"):
        return 3
    if name in ("chrome.exe", "msedge.exe", "firefox.exe"):
        return 4
    if name in ("cargo.exe", "rustc.exe", "link.exe", "cl.exe", "node.exe", "python.exe"):
        return 5
    if name in ("svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "explorer.exe"):
        return 6
    return 7


def sysmon_event(record):
    """One Sysmon record as (action, path, command_line, image, parent, pid, ppid, seconds)."""
    if "Sysmon" not in str(record.get("Channel", "")):
        return None
    try:
        event_id = int(record.get("EventID", -1))
    except (TypeError, ValueError):
        return None
    image = record.get("Image") or record.get("SourceImage") or ""
    command = record.get("CommandLine") or ""
    pid = int(record.get("ProcessId") or record.get("ProcessID") or 0) if str(record.get("ProcessId") or "").isdigit() else 0
    ppid = int(record.get("ParentProcessId") or 0) if str(record.get("ParentProcessId") or "").isdigit() else 0
    parent = record.get("ParentImage") or ""
    stamp = record.get("UtcTime") or record.get("EventTime") or ""
    seconds = 0.0
    try:
        # Sysmon writes `2020-07-22 00:18:47.123`; the numeric part after the
        # seconds is what orders two events in the same second.
        seconds = float(stamp[11:19].replace(":", "")) if len(stamp) >= 19 else 0.0
    except ValueError:
        seconds = 0.0

    if event_id == 1:
        return ("ProcessStarted", image, command, image, parent, pid, ppid, seconds)
    if event_id == 11:
        return ("FileWritten", record.get("TargetFilename"), "", image, parent, pid, ppid, seconds)
    if event_id in (12, 13, 14):
        return ("RegistryChanged", record.get("TargetObject"), "", image, parent, pid, ppid, seconds)
    if event_id == 7:
        return ("ImageLoaded", record.get("ImageLoaded"), "", image, parent, pid, ppid, seconds)
    if event_id in (23, 26):
        return ("FileDeleted", record.get("TargetFilename"), "", image, parent, pid, ppid, seconds)
    return None


def features(action, path, command, image, parent, gap_seconds):
    data = [0.0] * WIDTH
    data[ACTIONS[action]] = 1.0
    data[11 + path_class(path)] = 1.0
    data[18 + extension_class(path)] = 1.0
    data[24 + registry_class(path)] = 1.0
    data[27:31] = flags(command)
    data[31] = min(1.0, np.log10(max(gap_seconds, 0.0) + 1.0) / 6.0)
    data[33] = image_class(image) / 8.0
    data[34] = image_class(parent) / 8.0
    return data


def convert(path):
    sequences = {}
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed = sysmon_event(record)
            if parsed is None:
                continue
            action, target, command, image, parent, pid, ppid, seconds = parsed
            queue = sequences.setdefault(pid, [])
            gap = seconds - queue[-1][0] if queue else 0.0
            queue.append((seconds, features(action, target, command, image, parent, gap)))
    out = []
    for pid, events in sequences.items():
        events.sort(key=lambda item: item[0])
        vectors = [vector for _, vector in events][-LENGTH:]
        missing = LENGTH - len(vectors)
        out.append([[0.0] * WIDTH] * missing + vectors)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-sequences", type=int, default=20000)
    args = parser.parse_args()

    sequences = convert(args.input)
    sequences = sequences[: args.max_sequences]
    print("sequences: %d" % len(sequences))
    if not sequences:
        return 1
    x = np.array(sequences, dtype=np.float32)
    y = np.ones(len(sequences), dtype=np.float32)
    np.savez_compressed(args.out, x=x, y=y, family=np.array(["sysmon"] * len(sequences)))
    print("wrote %s: %s" % (args.out, x.shape))
    return 0


if __name__ == "__main__":
    sys.exit(main())
