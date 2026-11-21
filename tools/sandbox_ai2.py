#!/usr/bin/env python3
"""The sandbox model, with the features the first version lacked.

The first version counted API names. That cannot tell an administrator tool
that terminates processes from a dropper that does the same thing, because the
difference is in the arguments and the order, not the names.

This reads each API call's arguments as text and adds:

* what the arguments look like: a path under Temp, a path under Startup, an
  executable being written, a registry key under CurrentVersion\\Run, a URL,
  a command line naming a living-off-the-land tool;
* the sequence: hashed bigrams of (module, api) across the run, so a dropper's
  write-then-execute order is a feature and not an accident of counts;
* the same per-module and per-family counts as before.

Label hygiene is the other half: a run whose emulation stopped after a handful
of calls is not evidence of benign behaviour, it is evidence of an emulator that
could not proceed. Such runs are dropped from both classes rather than taught as
negatives or positives.

Usage: python tools/sandbox_ai2.py --malicious DIR --benign DIR [--out model.txt]
"""
import argparse
import glob
import json
import math
import os
import sys

import lightgbm as lgb
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from sandbox_analyze import analyse  # noqa: E402

MODULES = [
    "kernel32", "kernelbase", "ntdll", "user32", "advapi32", "shell32", "ole32",
    "oleaut32", "ws2_32", "wininet", "winhttp", "urlmon", "psapi", "shlwapi",
    "msvcrt", "crypt32", "bcrypt", "secur32", "iphlpapi", "dnsapi", "version",
    "setupapi", "wintrust", "rpcrt4", "winmm", "dbghelp",
]
TOOLS = [
    "powershell", "cmd", "certutil", "bitsadmin", "mshta", "wscript", "cscript",
    "rundll32", "regsvr32", "schtasks", "vssadmin", "wbadmin", "bcdedit",
    "wevtutil", "net user", "net localgroup", "sc create", "reg add", "wmic",
    "taskkill", "curl", "bitsadmin",
]
PATHS = {
    "temp": ("\\temp\\", "/tmp/", "\\appdata\\local\\temp"),
    "startup": ("\\startup\\", "currentversion\\run", "\\start menu\\programs"),
    "windows": ("c:\\windows\\", "\\system32\\"),
    "user": ("c:\\users\\"),
    "program": ("c:\\program files"),
}


def arguments(event):
    values = []
    for argument in event.get("args") or []:
        for key in ("value", "display"):
            value = argument.get(key)
            if isinstance(value, str):
                values.append(value.lower())
    return " ".join(values)


def features(report):
    events = []
    for run in report.get("runs") or []:
        for event in run.get("events") or []:
            if event.get("event") == "api":
                events.append(event)
    if not events:
        return None
    total = len(events)
    modules = {name: 0 for name in MODULES}
    tools = {name: 0 for name in TOOLS}
    paths = {name: 0 for name in PATHS}
    apis = {}
    bigrams = {}
    previous = None
    wrote_executable = 0
    for event in events:
        api = (event.get("api_name") or "").lower()
        module = api.split(".")[0]
        if module in modules:
            modules[module] += 1
        apis[api] = apis.get(api, 0) + 1
        text = arguments(event)
        for name in TOOLS:
            if name in text or name in api:
                tools[name] += 1
        for name, needles in PATHS.items():
            if any(needle in text for needle in needles):
                paths[name] += 1
        if (".exe" in text or ".dll" in text) and ("createfile" in api or "writefile" in api):
            wrote_executable += 1
        if previous is not None:
            key = (previous + "|" + api)
            bigrams[key] = bigrams.get(key, 0) + 1
        previous = api
    counts = np.asarray(list(apis.values()), dtype=float)
    entropy = 0.0
    if len(counts) > 1:
        probabilities = counts / counts.sum()
        entropy = float(-(probabilities * np.log2(probabilities)).sum())
    score, findings, decisive = analyse(report)
    families = {finding["family"] for finding in findings}
    row = [min(total, 20000) / 20000.0, min(len(apis), 800) / 800.0, entropy / 10.0]
    row += [min(modules[name], 800) / 800.0 for name in MODULES]
    row += [min(tools[name], 20) / 20.0 for name in TOOLS]
    row += [min(paths[name], 50) / 50.0 for name in PATHS]
    row += [
        min(wrote_executable, 20) / 20.0,
        len(decisive) / 4.0,
        min(len(bigrams), 400) / 400.0,
    ]
    # 64 hashed bigram buckets: order, not just presence.
    buckets = [0.0] * 64
    for key, count in bigrams.items():
        value = 2166136261
        for byte in key.encode("utf-8", "ignore"):
            value ^= byte
            value = (value * 16777619) & 0xFFFFFFFF
        buckets[value % 64] += min(count, 10) / 10.0
    row += buckets
    return row


def load(directory, label, skip, minimum_events=40):
    rows, labels, names = [], [], []
    for path in sorted(glob.glob(os.path.join(directory, "*", "report.json"))):
        name = os.path.basename(os.path.dirname(path))
        if any(token.lower() in name.lower() for token in skip):
            continue
        try:
            report = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        events = sum(
            1 for run in report.get("runs") or [] for event in run.get("events") or []
            if event.get("event") == "api"
        )
        if events < minimum_events:
            continue
        row = features(report)
        if row is None:
            continue
        rows.append(row)
        labels.append(label)
        names.append(name)
    return rows, labels, names


def model():
    return lgb.LGBMClassifier(
        objective="binary", n_estimators=300, learning_rate=0.03,
        num_leaves=15, min_child_samples=3, feature_fraction=0.6,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=4, random_state=11,
        verbose=-1, reg_lambda=1.0,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--malicious", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--skip", default="aapt,AndroRat")
    parser.add_argument("--out", default=None)
    parser.add_argument("--minimum-events", type=int, default=40)
    args = parser.parse_args()

    skip = [token for token in args.skip.split(",") if token.strip()]
    rows, labels, names = [], [], []
    for label, directory in ((1, args.malicious), (0, args.benign)):
        part, part_labels, part_names = load(directory, label, skip, args.minimum_events)
        rows += part
        labels += part_labels
        names += part_names
    X = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int32)
    print("samples: %d malicious, %d benign, features %d" % (
        int(y.sum()), int((y == 0).sum()), X.shape[1]))

    scores = np.zeros(len(y))
    for index in range(len(y)):
        train = np.ones(len(y), dtype=bool)
        train[index] = False
        if y[train].sum() == 0 or (y[train] == 0).sum() == 0:
            continue
        m = model()
        m.fit(X[train], y[train])
        scores[index] = float(m.predict_proba(X[index:index + 1])[:, 1][0])

    malicious = scores[y == 1]
    benign = scores[y == 0]
    print("malicious: %s" % " ".join("%.3f" % v for v in sorted(malicious)))
    print("benign:    %s" % " ".join("%.3f" % v for v in sorted(benign)))
    threshold = float(benign.max()) if len(benign) else 0.5
    missed = int((malicious <= threshold).sum())
    print("zero-FP threshold %.4f -> miss %d/%d = %.1f%%" % (
        threshold, missed, len(malicious), 100.0 * missed / max(len(malicious), 1)))
    ordered = np.sort(malicious)
    allowed = int(math.floor(len(malicious) * 0.10))
    if len(ordered) > allowed:
        threshold10 = float(ordered[allowed]) - 1e-6
        fp = int((benign > threshold10).sum())
        print("<=10%% miss threshold %.4f -> FP %d/%d = %.1f%%" % (
            threshold10, fp, len(benign), 100.0 * fp / max(len(benign), 1)))
    if args.out:
        final = model()
        final.fit(X, y)
        final.booster_.save_model(args.out)
        print("saved", args.out)


if __name__ == "__main__":
    main()
