#!/usr/bin/env python3
"""Prove the pack works end to end: one sample, one behaviour, one summary.

MEMZ reaches `shell32!ShellExecuteW("C:\\loader.exe", "/watchdog")` before it
exits. That call is not implemented in MWEmu, so it appears in the trace as
`unsupported`. The whole point of the wrapper is that the argument is still
evidence: the pack must turn it into a process-creation finding through the same
analyser the rest of the sandbox uses.

Usage: python selftest.py [--engine PATH] [--sample PATH]
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import runner  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", default=runner.__dict__.get(
        "DEFAULT_ENGINE", r"C:\Users\wensz\Downloads\mwemu-src\target\release\mwemu.exe"))
    parser.add_argument("--sample", default=r"C:\Users\wensz\Downloads\wenle-av\target\sandbox\MEMZ.exe")
    parser.add_argument("--seconds", type=int, default=20)
    args = parser.parse_args()

    if not os.path.exists(args.engine):
        print("engine missing:", args.engine)
        return 1
    if not os.path.exists(args.sample):
        print("sample missing:", args.sample)
        return 1
    out = os.path.join(os.environ.get("TEMP", "."), "mwemu-pack-selftest")
    result = runner.run(args.sample, out, args.engine, args.seconds)
    if not result["ok"]:
        print("FAILED to run:", result)
        return 1
    summary = runner.analyse(out)
    events = result["report"]["runs"][0]["events"]
    shell = [event for event in events if event["api_name"].startswith("shell32.")]
    families = {finding["family"] for finding in summary["findings"]}
    checks = {
        "trace has shell32 calls": len(shell) > 0,
        "ShellExecute carries a path": any(
            "loader.exe" in (argument.get("value") or "").lower()
            for event in shell for argument in event["args"]),
        "analyser produced a finding": len(summary["findings"]) > 0,
        "summary.json written": os.path.exists(os.path.join(out, "summary.json")),
    }
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    print("score:", summary["score"], "families:", sorted(families))
    if shell:
        print("first shell event:", json.dumps(shell[0])[:300])
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
