#!/usr/bin/env python3
"""Every language held out in turn.

The model has to recognise a language it was never trained on. The earlier
measurements only did this for batch and Python; this walks all seven script
languages the corpus carries, trains once per language and reports recall at
three false-positive rates.

Usage: python tools/script_holdouts.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

GROUPS = [
    ("batch", (".bat", ".cmd")),
    ("powershell", (".ps1", ".psm1")),
    ("python", (".py",)),
    ("javascript", (".js",)),
    ("vbscript", (".vbs",)),
    ("hta", (".hta",)),
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--malicious-limit", type=int, default=3000)
    parser.add_argument("--benign-per-extension", type=int, default=1200)
    parser.add_argument("--only", default=None)
    args = parser.parse_args()

    rows = []
    rows += [(d, e, 1) for d, e, l in read_parquet_malicious(args.scripts, args.malicious_limit)]
    rows += read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: args.benign_per_extension
                                   for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})
    print("rows:", len(rows), flush=True)

    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    languages = np.asarray([ext for _, ext, _ in rows])
    matrix = vectorize(rows)

    for name, extensions in GROUPS:
        if args.only and name != args.only:
            continue
        held = np.isin(languages, extensions)
        if held.sum() == 0:
            continue
        model = lgb.LGBMClassifier(
            objective="binary", n_estimators=800, learning_rate=0.05,
            num_leaves=127, min_child_samples=10, feature_fraction=0.3,
            bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
        )
        model.fit(matrix[~held], labels[~held])
        probability = model.predict_proba(matrix[held])[:, 1]
        truth = labels[held]
        benign = probability[truth == 0]
        line = "%-12s malicious %4d" % (name, int(truth.sum()))
        for value in (0.01, 0.001):
            threshold = float(np.quantile(benign, 1.0 - value)) if len(benign) else 0.5
            recall = float((probability[truth == 1] > threshold).mean()) if truth.sum() else 0.0
            line += "  FPR %.1f%% -> %.1f%%" % (100 * value, 100 * recall)
        print(line, flush=True)


if __name__ == "__main__":
    main()
