#!/usr/bin/env python3
"""Does the script model catch real batch scripts it has never seen?

The synthetic corpus carried the held-out language to 89.8% at best, and the
number moved when the template mix changed. The honest test is real scripts:
seventeen batch and VBScript files from public red-team repositories, held out
of training entirely, scored at the threshold a 0.1% false-positive rate sets on
benign scripts.

Usage: python tools/script_real_eval.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--malicious-limit", type=int, default=3000)
    args = parser.parse_args()

    rows = []
    rows += [(d, e, 1) for d, e, l in read_parquet_malicious(args.scripts, args.malicious_limit)]
    rows += read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: 120 for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})

    real_dir = os.path.join(args.scripts, "real")
    real = read_directory(real_dir, 1)
    print("training rows %d, real held-out %d" % (len(rows), len(real)))

    matrix = vectorize(rows)
    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=400, learning_rate=0.05,
        num_leaves=63, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix, labels)
    benign_probability = model.predict_proba(matrix[labels == 0])[:, 1]

    real_matrix = vectorize(real)
    real_probability = model.predict_proba(real_matrix)[:, 1]
    for value in (0.01, 0.001):
        threshold = float(np.quantile(benign_probability, 1.0 - value))
        caught = int((real_probability > threshold).sum())
        print("FPR %.3f -> real recall %.1f%% (%d/%d), threshold %.4f"
              % (value, 100.0 * caught / len(real), caught, len(real), threshold))
        for (data, extension, _), score in zip(real, real_probability):
            mark = "caught" if score > threshold else "missed"
            print("   %-8s %.3f %s %s" % (extension, score, mark, data[:40]))


if __name__ == "__main__":
    main()
