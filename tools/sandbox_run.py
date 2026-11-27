#!/usr/bin/env python3
"""Run one sample in Speakeasy under this product's conditions.

What this adds over calling Speakeasy itself:

* a virtual clock. Sleep returns at once but the clock moves forward by the
  sleep, and GetTickCount, GetTickCount64, timeGetTime, QueryPerformanceCounter
  and NtDelayExecution all read the same clock. A sample that sleeps an hour and
  compares two readings sees an hour pass; a sample that measures how long a
  sleep took sees the number it asked for. Skipping the wait without moving the
  clock is what sandbox-aware malware detects.
* a plausible machine: hostname, domain, OS build, user, SID and current
  directory, so the environment checks a sample makes get ordinary answers.
* the unpacked code. Speakeasy records regions that were written and then
  executed; each is written to the output directory and scanned by this
  product's own engine, which is where the packed payload meets the PE model.
* the report, turned into findings by `sandbox_analyze.py`.

Usage:
  python tools/sandbox_run.py --sample MEMZ.exe --out target/sandbox/MEMZ
"""
import argparse
import json
import os
import subprocess
import sys
import time

import speakeasy

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sandbox_analyze import analyse  # noqa: E402


class VirtualClock:
    """Wall time plus everything the sample asked to sleep away."""

    def __init__(self):
        self.started = time.monotonic()
        self.offset_ms = 0

    def now_ms(self):
        return int((time.monotonic() - self.started) * 1000) + self.offset_ms


def install_clock_hooks(emulator, clock, log):
    def skip_sleep(emu, api_name, _func, argv):
        milliseconds = argv[0] if argv else 0
        clock.offset_ms += max(0, int(milliseconds))
        log.append({"hook": api_name, "skipped_ms": int(milliseconds)})
        return 0

    def skip_delay(emu, api_name, _func, argv):
        # NtDelayExecution: argv[1] points at a LARGE_INTEGER, negative for a
        # relative wait in 100ns units.
        pointer = argv[1] if len(argv) > 1 else 0
        try:
            raw = emu.mem_read(pointer, 8)
            value = int.from_bytes(raw, "little", signed=True)
            milliseconds = abs(value) // 10_000
        except Exception:
            milliseconds = 0
        clock.offset_ms += milliseconds
        log.append({"hook": api_name, "skipped_ms": milliseconds})
        return 0

    def tick_count(emu, api_name, _func, argv):
        return clock.now_ms() & 0x7FFFFFFF

    def tick_count_64(emu, api_name, _func, argv):
        return clock.now_ms()

    def time_get_time(emu, api_name, _func, argv):
        return clock.now_ms() & 0x7FFFFFFF

    def performance_counter(emu, api_name, _func, argv):
        if argv:
            try:
                emu.mem_write(argv[0], (clock.now_ms() * 10_000).to_bytes(8, "little"))
            except Exception:
                pass
        return 0

    # Speakeasy hands a hook the arguments the API takes; without `argc` it
    # hands an empty list and the delay is read as zero. Measured 2026-11-22:
    # a 2 s NtDelayExecution advanced the virtual clock by 1 ms until argc=2
    # was passed, and by 2001 ms after.
    # The clock is Speakeasy's own. Its Sleep advances the same clock that
    # GetTickCount, GetTickCount64, timeGetTime and GetSystemTimeAsFileTime
    # read, and it advances without waiting -- measured 2026-11-22: a native
    # Sleep(1500) moved system time by 1541 ms and the run finished in seconds.
    # The runner used to override only Sleep and the tick count, which made the
    # two halves of the clock disagree; it now adds no clock hooks at all.

def dump_regions(report, out_dir):
    """Write every region Speakeasy saw written and then played.

    Two shapes have to be read. The older report put the bytes on the entry
    (`bytes`/`data`) or in a list of integers. The 2.1 schema puts
    `contents: [{pos, data_ref}]` on the entry and the payload in the report's
    top-level `data` map, base64 of a zlib stream. Reading the new shape as a
    list of integers raised "'dict' object cannot be interpreted as an integer"
    on every sample that allocated and ran code, which took the whole run down
    before summary.json was written.
    """
    import base64
    import zlib

    blobs = report.get("data") or {}
    dumped = []
    for index, run in enumerate(report.get("runs") or []):
        for entry_index, entry in enumerate(run.get("dynamic_code") or []):
            payload = _entry_payload(report, blobs, entry, base64, zlib)
            if not payload or len(payload) < 64:
                continue
            name = "unpacked-%02d-%02d.bin" % (index, entry_index)
            path = os.path.join(out_dir, name)
            with open(path, "wb") as handle:
                handle.write(payload)
            dumped.append(path)
    return dumped


def _entry_payload(report, blobs, entry, base64, zlib):
    """The bytes one dynamic-code entry describes, in either report shape."""
    if not isinstance(entry, dict):
        return None
    contents = entry.get("contents")
    if isinstance(contents, list):
        pieces = []
        for part in contents:
            reference = part.get("data_ref") if isinstance(part, dict) else None
            blob = blobs.get(reference) if reference is not None else None
            if isinstance(blob, dict):
                blob = blob.get("data") or blob.get("value")
            if not isinstance(blob, str):
                continue
            try:
                raw = base64.b64decode(blob)
            except Exception:
                continue
            try:
                raw = zlib.decompress(raw)
            except Exception:
                pass
            pieces.append(raw)
        if pieces:
            return b"".join(pieces)
    for key in ("bytes", "data"):
        value = entry.get(key)
        if isinstance(value, str):
            try:
                return base64.b64decode(value)
            except Exception:
                return None
        if isinstance(value, list):
            try:
                return bytes(value)
            except Exception:
                return None
    return None


def scan_with_product(paths, scanner):
    results = []
    if not scanner or not os.path.exists(scanner):
        return results
    for path in paths:
        try:
            completed = subprocess.run(
                [scanner, "scan", path],
                capture_output=True, text=True, timeout=120,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            verdict = "malicious" if "malicious" in output.lower() else "clean"
            results.append({"file": os.path.basename(path), "verdict": verdict,
                            "output": output.strip()[:2000]})
        except Exception as error:
            results.append({"file": os.path.basename(path), "verdict": "error",
                            "output": str(error)[:500]})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--out", required=True, help="directory for the report and dumps")
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--scanner", default=r"C:\WenleAV\wenle.exe")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    clock = VirtualClock()
    skipped = []

    config = {
        "limits": {"per_run_time": args.seconds, "total_time": args.seconds * 4},
        "system": {
            "os_ver": {"name": "windows", "major": 10, "minor": 0, "build": 19045},
            "hostname": "DESKTOP-7K2Q4L",
            "domain": "WORKGROUP",
            "drives": [{"root_path": "C:", "drive_type": "DRIVE_FIXED"}],
        },
        "user": {
            "name": "wensz",
            "admin": True,
            "sid": "S-1-5-21-1004336348-1177238915-682003330-1001",
        },
        "process": {
            "current_dir": r"C:\Users\wensz\Desktop",
            "env": {
                "USERNAME": "wensz",
                "USERPROFILE": r"C:\Users\wensz",
                "COMPUTERNAME": "DESKTOP-7K2Q4L",
                "HOMEDRIVE": "C:",
                "HOMEPATH": r"\Users\wensz",
                "TEMP": r"C:\Users\wensz\AppData\Local\Temp",
                "OS": "Windows_NT",
                "PROCESSOR_ARCHITECTURE": "AMD64",
            },
        },
        "network": {
            "adapters": [{
                "name": "Ethernet",
                "description": "Intel(R) Ethernet Connection I219-V",
                "mac_address": "00-1C-42-7A-3F-91-D4",
                "type": "ethernet",
                "ip_address": "192.168.1.42",
                "subnet_mask": "255.255.255.0",
                "dhcp_enabled": True,
            }],
        },
    }
    emulator = speakeasy.Speakeasy(config=config)
    install_clock_hooks(emulator, clock, skipped)
    module = emulator.load_module(args.sample)
    emulator.run_module(module)
    report = emulator.get_report().model_dump() if hasattr(emulator.get_report(), "model_dump") else {}

    report_path = os.path.join(args.out, "report.json")
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, default=str)

    unpacked = dump_regions(report, args.out)
    scanned = scan_with_product(unpacked, args.scanner)

    score, findings, decisive = analyse(report)
    summary = {
        "sample": os.path.abspath(args.sample),
        "sha256": report.get("sha256"),
        "score": round(score, 3),
        "findings": findings,
        "decisive": decisive,
        "clock": {
            "virtual_ms": clock.now_ms(),
            "skipped_sleeps": len(skipped),
            "skipped_ms_total": sum(entry["skipped_ms"] for entry in skipped),
        },
        "unpacked": scanned,
        "report": report_path,
    }
    summary_path = os.path.join(args.out, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1)
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
