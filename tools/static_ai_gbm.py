#!/usr/bin/env python3
"""Static AI with LightGBM on the larger sample, judged on unseen families.

Histogram gradient boosting needed a float64 copy of the design matrix and ran
this machine out of memory past 150,000 samples. LightGBM bins the features once
and trains from the bins, which is why it can carry the larger sample here.

The number that matters is recall on families that were held out of training
entirely, at the false-positive rates a product can carry.

Usage: python tools/static_ai_gbm.py --jsonl combined3.jsonl --limit 230000
"""
import argparse
import io
import json
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from static_ai_full import vector


def read_file(path, limit):
    rows, labels, appeared, families = [], [], [], []
    with io.open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if len(labels) >= limit:
                break
            try:
                item = json.loads(line)
                label = int(item["label"])
            except (ValueError, KeyError, TypeError):
                continue
            if label not in (0, 1):
                continue
            rows.append(np.asarray(vector(item), dtype=np.float32))
            labels.append(label)
            appeared.append(int(str(item.get("appeared", "0")).replace("-", "") or 0))
            families.append(str(item.get("avclass", "") or ""))
    x = np.stack(rows)
    return (x, np.asarray(labels, dtype=np.float32),
            np.asarray(appeared, dtype=np.int64), np.asarray(families))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--limit", type=int, default=230000)
    parser.add_argument("--leaves", type=int, default=255)
    parser.add_argument("--trees", type=int, default=500)
    args = parser.parse_args()

    x, y, appeared, families = read_file(args.jsonl, args.limit)
    del appeared
    print("samples %d, features %d, malicious %.1f%%"
          % (len(x), x.shape[1], 100 * y.mean()), flush=True)

    malware_families = sorted({f for f, label in zip(families, y) if label == 1 and f})
    held = {family for index, family in enumerate(malware_families) if index % 4 == 0}
    is_held = np.array([family in held for family in families])
    print("held-out families %d, samples %d" % (len(held), int(is_held.sum())), flush=True)

    train = ~is_held
    test_benign = (~is_held) & (y == 0)
    model = lgb.LGBMClassifier(
        objective="binary",
        n_estimators=args.trees,
        learning_rate=0.05,
        num_leaves=args.leaves,
        min_child_samples=20,
        feature_fraction=0.4,
        bagging_fraction=0.8,
        bagging_freq=1,
        n_jobs=6,
        random_state=11,
        verbose=-1,
    )
    model.fit(x[train], y[train])
    print("trained", flush=True)

    benchmark = np.where(test_benign)[0]
    if len(benchmark) > 60000:
        benchmark = np.random.default_rng(3).choice(benchmark, 60000, replace=False)
    benign = model.predict_proba(x[benchmark])[:, 1]
    malicious = model.predict_proba(x[is_held & (y == 1)])[:, 1]
    print("benign %d, malicious %d" % (len(benign), len(malicious)), flush=True)
    for fpr in (0.01, 0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        print("   FPR %.4f -> held-out family recall %.1f%%"
              % (fpr, 100 * (malicious >= threshold).mean()), flush=True)
    zero = float(benign.max())
    print("   FPR 0 -> recall %.1f%% (threshold %.4f)"
          % (100 * (malicious >= zero).mean(), zero), flush=True)


if __name__ == "__main__":
    sys.exit(main())
