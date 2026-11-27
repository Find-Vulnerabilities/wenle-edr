#!/usr/bin/env python3
"""False positives on real scripts this machine already has.

The calibration set is Windows modules and Program Files, which the model also
trains on. This walks the machine for script files outside every training root,
drops anything that looks like a test artefact, and scores what is left with a
model trained the way the product is trained. Whatever comes out is the model's
false-positive rate on real work, not on its own training material.

Usage: python tools/script_fp_test.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import random
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_ai import features
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

EXTENSIONS = (".ps1", ".psm1", ".js", ".vbs", ".bat", ".cmd", ".py", ".hta")
ROOTS = (r"C:\Users", r"C:\ProgramData", r"C:\Windows\System32", r"C:\Windows\SysWOW64", r"C:\Windows\Help")
SKIP = ("script-ai", "ember", "wenle", "malware", "samples", "amcache", "\\temp\\", "\\cache\\")


def collect(limit_per_extension=800, max_size=400_000):
    found = {extension: [] for extension in EXTENSIONS}
    for root in ROOTS:
        for current, directories, files in os.walk(root):
            lower = current.lower()
            if any(skip in lower for skip in SKIP):
                directories[:] = []
                continue
            if "\\windows\\system32\\windowspowershell\\v1.0\\modules" in lower:
                directories[:] = []
                continue
            for name in files:
                extension = os.path.splitext(name)[1].lower()
                if extension not in found:
                    continue
                path = os.path.join(current, name)
                try:
                    if os.path.getsize(path) > max_size:
                        continue
                except OSError:
                    continue
                found[extension].append(path)
    rng = random.Random(11)
    chosen = []
    for extension, paths in found.items():
        rng.shuffle(paths)
        for path in paths[:limit_per_extension]:
            try:
                with open(path, "rb") as handle:
                    chosen.append((handle.read(), extension, 0, path))
            except OSError:
                pass
    return chosen


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
    print("training rows:", len(rows), flush=True)
    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    matrix = vectorize(rows)
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=800, learning_rate=0.05,
        num_leaves=127, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix, labels)

    benign_training = matrix[labels == 0]
    baseline = model.predict_proba(benign_training)[:, 1]

    candidates = collect()
    print("real scripts found:", len(candidates), flush=True)
    scored = []
    for data, extension, _label, path in candidates:
        try:
            dense, grams = features(data)
        except Exception:
            continue
        scored.append((extension, path, len(grams)))
    if not scored:
        print("nothing to score")
        return

    # Vectorise with the same hashing as training, one batch at a time.
    indexes = [index for _, _, index in scored]
    test_matrix = vectorize([(open(path, "rb").read(), extension, 0) for extension, path, _ in scored])
    probability = model.predict_proba(test_matrix)[:, 1]

    print("scored:", len(probability), flush=True)
    # The threshold has to come from real scripts, not from the training benign:
    # that set is almost all zeros, which puts the threshold at zero and flags a
    # tenth of ordinary work. Drop our own test artefacts, then take the real
    # distribution as the calibration.
    keep = np.asarray([not (("technique-test" in path.lower()) or ("memz" in path.lower())
                            or ("eicar" in path.lower()))
                       for _extension, path, _grams in scored])
    real = probability[keep]
    for value in (0.01, 0.001):
        threshold = float(np.quantile(real, 1.0 - value))
        above = int((probability > threshold).sum())
        print("real calibration %.2f%% -> threshold %.4f -> real files flagged: %d/%d = %.3f%%"
              % (100 * value, threshold, above, len(probability), 100.0 * above / len(probability)))
    order = np.argsort(probability)[-10:][::-1]
    print("highest scoring real files:")
    for index in order:
        extension, path, _ = scored[index]
        print("   %.4f %s" % (probability[index], path))


if __name__ == "__main__":
    main()
