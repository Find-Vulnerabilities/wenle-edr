#!/usr/bin/env python3
"""The operating point: one threshold, two numbers.

Calibrate the threshold so that real, non-training scripts are flagged at 0.1%,
then measure what that threshold misses on attacks the model was not trained on.
Both numbers belong to the same model and the same line on the score axis.

Usage: python tools/script_operating_point.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import random
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

LANGUAGES = {
    "batch": (".bat", ".cmd"),
    "powershell": (".ps1", ".psm1"),
    "python": (".py",),
    "javascript": (".js",),
    "vbscript": (".vbs",),
    "hta": (".hta",),
}
SKIP = ("script-ai", "ember", "wenle", "malware", "samples")


def real_files(limit=2500, max_size=300_000):
    roots = [r"C:\Users\wensz\Downloads", r"C:\Users\wensz\Desktop",
             r"C:\Users\wensz\AppData\Local\Programs", r"C:\Program Files\nodejs"]
    found = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for current, directories, files in os.walk(root):
            lower = current.lower()
            if any(skip in lower for skip in SKIP):
                directories[:] = []
                continue
            for name in files:
                if os.path.splitext(name)[1].lower() not in (".js", ".mjs", ".cjs", ".jsx", ".py"):
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.getsize(path) > max_size:
                        continue
                except OSError:
                    continue
                found.append(path)
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
    synthetic_attack = read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rng = random.Random(11)
    by_language = {}
    for row in synthetic_attack:
        by_language.setdefault(row[1], []).append(row)
    holdout = []
    training = []
    for extension, group in by_language.items():
        rng.shuffle(group)
        cut = max(1, len(group) // 5)
        holdout += group[:cut]
        training += group[cut:]
    rows += training
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: args.benign_per_extension
                                   for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})
    print("training rows %d, attack holdout %d" % (len(rows), len(holdout)), flush=True)

    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    matrix = vectorize(rows)
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=800, learning_rate=0.05,
        num_leaves=127, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix, labels)

    paths = real_files()
    data = [(open(path, "rb").read(), os.path.splitext(path)[1].lower(), 0) for path in paths]
    real = model.predict_proba(vectorize(data))[:, 1]
    half = len(real) // 2
    calibration, test = real[:half], real[half:]

    holdout_matrix = vectorize([(d, e, 0) for d, e, _ in holdout])
    attack = model.predict_proba(holdout_matrix)[:, 1]
    attack_languages = np.asarray([e for _, e, _ in holdout])

    for value in (0.001, 0.0001):
        threshold = float(np.quantile(calibration, 1.0 - value))
        fp = int((test > threshold).sum())
        missed = 0
        total = 0
        line = "threshold %.4f (real benign %.2f%%) | real FP %d/%d = %.2f%% | " % (
            threshold, 100 * value, fp, len(test), 100.0 * fp / max(len(test), 1))
        for name, group in LANGUAGES.items():
            mask = np.isin(attack_languages, group)
            if mask.sum() == 0:
                continue
            recall = float((attack[mask] > threshold).mean())
            missed += int((attack[mask] <= threshold).sum())
            total += int(mask.sum())
            line += "%s %.1f%% | " % (name, 100 * recall)
        line += "overall miss %d/%d = %.1f%%" % (missed, total, 100.0 * missed / max(total, 1))
        print(line, flush=True)


if __name__ == "__main__":
    main()
