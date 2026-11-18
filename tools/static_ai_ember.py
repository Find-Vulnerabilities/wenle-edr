#!/usr/bin/env python3
"""First static-AI number on a real dataset: EMBER 2018.

Each line of the test file is one labelled sample: a SHA-256, a label, and the
2,381 features Elastic's Ember computes from the PE. The question is not whether
a tree ensemble can separate them -- everyone's does -- but where the operating
point sits: recall at a false-positive rate a product can live with.

Usage: python tools/static_ai_ember.py --jsonl <test_features.jsonl> --out npz
"""
import argparse
import json
import sys

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score


def load(path, limit):
    rows = []
    labels = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if len(labels) >= limit:
                break
            try:
                item = json.loads(line)
                features = item["features"]
                label = item["label"]
            except (ValueError, KeyError):
                continue
            rows.append(features)
            labels.append(label)
    x = np.asarray(rows, dtype=np.float32)
    y = np.asarray(labels, dtype=np.float32)
    return x, y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=200000)
    parser.add_argument("--iterations", type=int, default=120)
    args = parser.parse_args()

    x, y = load(args.jsonl, args.limit)
    print("loaded %d samples, %d features, %.1f%% malicious"
          % (len(x), x.shape[1], 100.0 * y.mean()))
    np.savez_compressed(args.out, x=x, y=y)

    order = np.random.default_rng(7).permutation(len(x))
    cut = int(len(x) * 0.8)
    train, test = order[:cut], order[cut:]
    model = HistGradientBoostingClassifier(
        max_iter=args.iterations,
        learning_rate=0.1,
        max_leaf_nodes=31,
        early_stopping=True,
        random_state=7,
    )
    model.fit(x[train], y[train])
    probability = model.predict_proba(x[test])[:, 1]
    auc = roc_auc_score(y[test], probability)

    benign = probability[y[test] == 0]
    malicious = probability[y[test] == 1]
    for fpr in (0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        recall = (malicious >= threshold).mean()
        print("FPR %.4f -> threshold %.4f, recall %.1f%%"
              % (fpr, threshold, 100 * recall))
    print("AUC %.4f on %d held-out samples" % (auc, len(test)))


if __name__ == "__main__":
    sys.exit(main())
