#!/usr/bin/env python3
"""False positives on real JavaScript, from real JavaScript.

The TypeScript files of a Next.js project are not JavaScript, and the model has
never been trained on TypeScript, so scoring them says nothing. This collects
.js, .mjs, .cjs and .jsx files from places where they were installed for people
to use -- a project's node_modules, the Node.js installation, editor resources --
splits them in half, calibrates the threshold on one half and measures the false
positive rate on the other half, which the calibration never saw.

Usage: python tools/script_js_fp.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import random
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx")
ROOTS = [
    r"C:\Users\wensz\Desktop\saas-pdf\node_modules",
    r"C:\Users\wensz\AppData\Local\Programs",
    r"C:\Program Files\nodejs",
    r"C:\Users\wensz\AppData\Roaming\npm",
    r"C:\Users\wensz\AppData\Local\Microsoft\EdgeWebView",
]


def collect(limit=4000, max_size=300_000):
    found = []
    for root in ROOTS:
        if not os.path.isdir(root):
            continue
        for current, directories, files in os.walk(root):
            for name in files:
                if os.path.splitext(name)[1].lower() not in EXTENSIONS:
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.getsize(path) > max_size:
                        continue
                except OSError:
                    continue
                found.append(path)
                if len(found) >= limit * 2:
                    break
            if len(found) >= limit * 2:
                break
    random.Random(11).shuffle(found)
    return found[:limit]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--malicious-limit", type=int, default=3000)
    parser.add_argument("--benign-per-extension", type=int, default=600)
    args = parser.parse_args()

    rows = []
    rows += [(d, e, 1) for d, e, l in read_parquet_malicious(args.scripts, args.malicious_limit)]
    rows += read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: args.benign_per_extension
                                   for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})
    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    matrix = vectorize(rows)
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=800, learning_rate=0.05,
        num_leaves=127, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix, labels)

    paths = collect()
    print("real javascript files:", len(paths), flush=True)
    data = []
    kept = []
    for path in paths:
        try:
            with open(path, "rb") as handle:
                data.append((handle.read(), os.path.splitext(path)[1].lower(), 0))
            kept.append(path)
        except OSError:
            pass
    probability = model.predict_proba(vectorize(data))[:, 1]

    half = len(probability) // 2
    calibration, test = probability[:half], probability[half:]
    print("calibration %d, test %d" % (len(calibration), len(test)), flush=True)
    for value in (0.01, 0.001):
        threshold = float(np.quantile(calibration, 1.0 - value))
        flagged = int((test > threshold).sum())
        print("FPR %.2f%% -> threshold %.4f -> test files flagged %d/%d = %.2f%%"
              % (100 * value, threshold, flagged, len(test), 100.0 * flagged / len(test)), flush=True)
    print("score median %.4f, 99th %.4f, max %.4f"
          % (float(np.median(probability)), float(np.quantile(probability, 0.99)), float(probability.max())), flush=True)
    order = np.argsort(probability)[-8:][::-1]
    print("highest scoring real javascript:")
    for index in order:
        safe = kept[index].encode("ascii", "replace").decode("ascii")
        print("   %.4f %s" % (probability[index], safe), flush=True)


if __name__ == "__main__":
    main()
