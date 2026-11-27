#!/usr/bin/env python3
"""Score a real JavaScript project.

`C:\\Users\\wensz\\Desktop\\saas-pdf` is a working project, not a corpus: its
files were written by a person for a product, so whatever the script model does
to them is the false-positive rate on real JavaScript. The thresholds come from
the machine-wide real-script calibration measured separately.

Usage: python tools/script_project_test.py --scripts C:\\...\\script-ai --project C:\\...\\saas-pdf
"""
import argparse
import os
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

EXTENSIONS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--max-size", type=int, default=300_000)
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

    paths = []
    for current, directories, files in os.walk(args.project):
        if "node_modules" in directories:
            directories.remove("node_modules")
        for name in files:
            if os.path.splitext(name)[1].lower() not in EXTENSIONS:
                continue
            full = os.path.join(current, name)
            try:
                if os.path.getsize(full) > args.max_size:
                    continue
            except OSError:
                continue
            paths.append(full)
    print("project files:", len(paths), flush=True)
    if not paths:
        return

    data = []
    for path in paths:
        try:
            with open(path, "rb") as handle:
                data.append((handle.read(), os.path.splitext(path)[1].lower(), 0))
        except OSError:
            pass
    probability = model.predict_proba(vectorize(data))[:, 1]
    order = np.argsort(probability)[::-1]

    for threshold in (0.7979, 1.0):
        flagged = int((probability > threshold).sum())
        print("threshold %.4f -> flagged %d/%d = %.2f%%"
              % (threshold, flagged, len(probability), 100.0 * flagged / len(probability)), flush=True)
    print("score median %.4f, 99th %.4f, max %.4f"
          % (float(np.median(probability)), float(np.quantile(probability, 0.99)), float(probability.max())), flush=True)
    print("highest scoring files:")
    for index in order[:10]:
        path = paths[index]
        safe = path.encode("ascii", "replace").decode("ascii")
        print("   %.4f %s" % (probability[index], safe), flush=True)


if __name__ == "__main__":
    main()
