#!/usr/bin/env python3
"""Which batch templates does the held-out language model miss, and why.

Held out all .bat/.cmd files, train on everything else, score the batch test
set, and print the misses grouped by their first command line. The grouping is
what says whether a miss is one template (fixable with a token) or a language
blind spot (needs data).

Usage: python tools/script_misses.py --scripts C:\\...\\script-ai
"""
import argparse
import io
import os
import sys
from collections import Counter

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

    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    languages = np.asarray([ext for _, ext, _ in rows])
    matrix = vectorize(rows)

    held = np.isin(languages, (".bat", ".cmd"))
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=400, learning_rate=0.05,
        num_leaves=63, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix[~held], labels[~held])
    scores = model.predict_proba(matrix[held])[:, 1]
    truth = labels[held]
    benign = scores[truth == 0]
    threshold = float(np.quantile(benign, 0.99))

    missed = []
    for (data, _ext, label), score in zip([row for row, is_held in zip(rows, held) if is_held], scores):
        if label == 1 and score <= threshold:
            text = data.decode("utf-8", "replace")
            first = next((line.strip() for line in text.splitlines() if line.strip()), "")[:70]
            missed.append(first)
    print("held-out malicious %d, missed %d at 1%% FPR (threshold %.4f)"
          % (int(truth.sum()), len(missed), threshold))
    with io.open(r"C:\Users\wensz\Downloads\wenle-av\target\script-misses.txt", "w", encoding="utf-8") as out:
        for line, count in Counter(missed).most_common(20):
            out.write("%2d  %s\n" % (count, line))


if __name__ == "__main__":
    main()
