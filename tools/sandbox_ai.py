#!/usr/bin/env python3
"""Train the sandbox behaviour model from Speakeasy runs.

The model this replaces was the driver story model, which cannot read sandbox
features. This one is trained on sandbox features only:

* per-module API counts (the modules a sample talks to),
* per-action counts (file write, registry, process start, image load, network),
* the sizes and the ratio of unique APIs, and the entropy of the call sequence,
* the skipped-sleep total from the virtual clock,
* the families `sandbox_analyze` reports.

The corpus is small, so the honest measurement is leave-one-out: every sample is
scored by a model trained without it. The reported number is the miss rate at a
threshold that produces no false positive on the same fold, plus the false
positive rate at a threshold that misses at most a tenth.

Usage: python tools/sandbox_ai.py --malicious DIR --benign DIR --out model.txt
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
    "oleaut32", "comctl32", "gdi32", "ws2_32", "wininet", "winhttp", "urlmon",
    "psapi", "shlwapi", "msvcrt", "ucrtbase", "crypt32", "bcrypt", "secur32",
    "iphlpapi", "dnsapi", "version", "setupapi", "wintrust", "msi", "rpcrt4",
    "comdlg32", "imm32", "winmm", "dbghelp",
]
ACTIONS = {
    "file": ("createfile", "writefile", "copyfile", "setfileattributes"),
    "image": ("loadlibrary",),
    "process": ("createprocess", "shellexecute", "winexec"),
    "delete": ("deletefile",),
    "rename": ("movefile",),
    "registry": ("regsetvalue", "regcreatekey", "regdelete"),
    "network": ("internetopen", "httpsendrequest", "wsaconnect", "connect", "send", "recv", "urldownloadtofile", "winhttp"),
}


def action_of(api):
    short = api.lower()
    for name, needles in ACTIONS.items():
        if any(needle in short for needle in needles):
            return name
    return "other"


def features(report):
    events = []
    for run in report.get("runs") or []:
        for event in run.get("events") or []:
            if event.get("event") == "api":
                events.append(event.get("api_name") or "")
    total = len(events)
    modules = {name: 0 for name in MODULES}
    actions = {name: 0 for name in list(ACTIONS) + ["other"]}
    apis = {}
    for api in events:
        module = api.split(".")[0].lower()
        if module in modules:
            modules[module] += 1
        actions[action_of(api)] += 1
        apis[api] = apis.get(api, 0) + 1
    counts = np.asarray(list(apis.values()), dtype=float)
    entropy = 0.0
    if len(counts) > 1:
        probabilities = counts / counts.sum()
        entropy = float(-(probabilities * np.log2(probabilities)).sum())
    score, findings, decisive = analyse(report)
    families = {finding["family"] for finding in findings}
    row = [min(total, 10000) / 10000.0]
    row += [min(modules[name], 500) / 500.0 for name in MODULES]
    row += [actions[name] / max(total, 1) for name in list(ACTIONS) + ["other"]]
    row += [
        min(len(apis), 500) / 500.0,
        entropy / 8.0,
        1.0 if events else 0.0,
        len(decisive) / 4.0,
        1.0 if "injection" in families else 0.0,
        1.0 if "defence_tampering" in families else 0.0,
        1.0 if "credential_access" in families else 0.0,
        1.0 if "download" in families else 0.0,
    ]
    return row


def load(directory, label, skip=()):
    rows, labels, names = [], [], []
    for path in sorted(glob.glob(os.path.join(directory, "*", "report.json"))):
        try:
            report = json.load(open(path, encoding="utf-8"))
        except Exception:
            continue
        name = os.path.basename(os.path.dirname(path))
        if any(token.lower() in name.lower() for token in skip):
            continue
        rows.append(features(report))
        labels.append(label)
        names.append(os.path.basename(os.path.dirname(path)))
    return rows, labels, names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--malicious", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--out", default=None)
    parser.add_argument("--skip", default="")
    args = parser.parse_args()

    rows, labels, names = [], [], []
    for label, directory in ((1, args.malicious), (0, args.benign)):
        skip = [token for token in args.skip.split(",") if token.strip()]
        part, part_labels, part_names = load(directory, label, skip)
        rows += part
        labels += part_labels
        names += part_names
    X = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.int32)
    print("samples: %d malicious, %d benign, features %d" % (int(y.sum()), int((y == 0).sum()), X.shape[1]))

    def model():
        return lgb.LGBMClassifier(
            objective="binary", n_estimators=200, learning_rate=0.05,
            num_leaves=7, min_child_samples=2, feature_fraction=0.7,
            bagging_fraction=0.8, bagging_freq=1, n_jobs=4, random_state=11,
            verbose=-1,
        )

    # Leave-one-out: every sample is scored by a model that never saw it.
    scores = np.zeros(len(y), dtype=float)
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
    print("malicious scores: %s" % " ".join("%.3f" % value for value in sorted(malicious)))
    print("benign scores:    %s" % " ".join("%.3f" % value for value in sorted(benign)))
    # Zero false positives: the threshold above every benign score.
    threshold = float(benign.max()) if len(benign) else 0.5
    missed = int((malicious <= threshold).sum())
    print("zero-FP threshold %.4f -> miss %d/%d = %.1f%%" % (
        threshold, missed, len(malicious), 100.0 * missed / max(len(malicious), 1)))
    # At most ten percent missed: the lowest threshold that achieves it.
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
        print("model saved to", args.out)


if __name__ == "__main__":
    main()
