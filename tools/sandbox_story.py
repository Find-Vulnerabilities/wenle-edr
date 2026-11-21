#!/usr/bin/env python3
"""Score a sandbox run with the behaviour story model.

The behaviour model reads 64 events of 47 numbers each (crates/av-behaviour's
`sequence.rs`). The sandbox records Windows API calls instead. This maps one
onto the other:

    CreateFile / WriteFile / CopyFile      -> action 1  (file written)
    LoadLibrary                            -> action 2  (image loaded)
    CreateProcess / ShellExecute / WinExec -> action 3  (process started)
    DeleteFile                             -> action 9  (file deleted)
    MoveFile                               -> action 8  (file renamed)
    RegSetValue / RegCreateKey / RegDelete -> action 10 (registry changed)
    network APIs                           -> action 6  (state changed: the
                                                          closest class; the
                                                          command-line columns
                                                          carry the download)
    anything else                          -> action 6

The gap column (32) is the log-scaled tick distance, the four command-line
flags (28-31) are set from the API name, and the tool bucket (39-46) is the FNV
hash of the API's module name. The path/extension/registry columns stay zero:
the sandbox records names as arguments, and inventing them would be worse than
leaving them empty.

The score is a number, not a verdict: it is compared with the thresholds in
`crates/av-scan/src/sandbox.rs`.

Usage: python tools/sandbox_story.py --report report.json [--model story.bin]
"""
import argparse
import json
import math
import os
import struct
import sys

MAGIC = 0x57414931
WIDTH = 47
LENGTH = 64


def load_model(path):
    data = open(path, "rb").read()
    offset = 0

    def u32():
        nonlocal offset
        value = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        return value

    def i32s(count):
        nonlocal offset
        value = list(struct.unpack_from("<%di" % count, data, offset))
        offset += 4 * count
        return value

    def f32s(count):
        nonlocal offset
        value = list(struct.unpack_from("<%df" % count, data, offset))
        offset += 4 * count
        return value

    if u32() != MAGIC:
        raise ValueError("not a story model")
    trees = u32()
    _features = u32()
    forest = []
    for _ in range(trees):
        leaves = u32()
        splits = leaves - 1
        split = i32s(splits)
        threshold = f32s(splits)
        left = i32s(splits)
        right = i32s(splits)
        leaf = f32s(leaves)
        forest.append((split, threshold, left, right, leaf))
    return forest


def score(forest, flat):
    total = 0.0
    for split, threshold, left, right, leaf in forest:
        node = 0
        while True:
            feature = split[node]
            value = flat[feature] if 0 <= feature < len(flat) else 0.0
            child = left[node] if value <= threshold[node] else right[node]
            if child < 0:
                total += leaf[~child]
                break
            node = child
    return 1.0 / (1.0 + math.exp(-total))


ACTIONS = {
    "createfile": 1, "writefile": 1, "copyfile": 1, "setfileattributes": 1,
    "loadlibrary": 2, "loadlibraryex": 2,
    "createprocess": 3, "shellexecute": 3, "shellexecuteex": 3, "winexec": 3,
    "deletefile": 9, "movefile": 8, "copyfileex": 1,
    "regsetvalue": 10, "regcreatekey": 10, "regdeletekey": 10, "regdeletevalue": 10,
    "internetopen": 6, "httpsendrequest": 6, "wsaconnect": 6, "connect": 6,
    "send": 6, "recv": 6, "urldownloadtofile": 6, "winhttpopen": 6,
}


def action_for(api_name):
    short = api_name.lower().replace("!", ".")
    for needle, action in ACTIONS.items():
        if needle in short:
            return action
    return 6


def fnv_tool(module):
    value = 2166136261
    for byte in module.encode("utf-8", "ignore"):
        value ^= byte
        value = (value * 16777619) & 0xFFFFFFFF
    return value % 8


def build_story(report):
    events = []
    for run in report.get("runs") or []:
        for event in run.get("events") or []:
            if event.get("event") == "api":
                events.append(event)
    events = events[-LENGTH:]
    if not events:
        return None, 0
    flat = [0.0] * (LENGTH * WIDTH)
    previous_tick = None
    for row, event in enumerate(events):
        base = row * WIDTH
        api = event.get("api_name") or ""
        flat[base + action_for(api)] = 1.0
        tick = (event.get("pos") or {}).get("tick")
        if isinstance(tick, int):
            gap = 1 if previous_tick is None else max(1, tick - previous_tick)
            previous_tick = tick
        else:
            gap = 1
        flat[base + 32] = min(1.0, math.log10(gap + 1.0) / 6.0)
        flat[base + 35 + 0] = 1.0 if any(word in api.lower() for word in ("shell", "process")) else 0.0
        flat[base + 33] = 4.0 / 8.0
        flat[base + 34] = 8.0 / 8.0
        module = api.split(".")[0].lower()
        flat[base + 39 + fnv_tool(module)] = 1.0
    return flat, len(events)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--model", default=None)
    args = parser.parse_args()

    model = args.model or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "crates", "av-behaviour", "data", "story.bin",
    )
    forest = load_model(model)
    report = json.load(open(args.report, encoding="utf-8"))
    flat, count = build_story(report)
    if flat is None:
        print(json.dumps({"events": 0, "behaviour_story": 0.0}))
        return
    value = score(forest, flat)
    print(json.dumps({"events": count, "behaviour_story": round(value, 4)}))


if __name__ == "__main__":
    main()
