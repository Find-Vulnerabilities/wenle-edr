#!/usr/bin/env python3
"""Static AI, measured the way the question asks.

Two splits that matter more than a random one:

  * time  -- train on what appeared before a date, test on what appeared after,
             which is what "unknown" means for a file scanner;
  * family -- hold whole avclass families out of training, so the score on them
             is about a malware family the model has never seen.

Reports recall at the two false-positive rates a product can carry (0.1% and
0.01%), plus AUC, and writes the trained model's shape for the port.

Usage: python tools/static_ai_final.py --jsonl X --limit 150000
"""
import argparse
import json
import sys

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

GENERAL = ["size", "vsize", "imports", "exports", "has_debug", "has_relocations",
           "has_resources", "has_signature", "has_tls", "symbols"]
HEADER = ["machine", "subsystem", "characteristics", "dll_characteristics"]
SECTION_KEYS = ["count"]


def vector(item):
    # The full vector: histogram, byte entropy, strings, general, header,
    # sections, hashed imports and exports, and the data directories.
    from static_ai_full import vector as full_vector
    return full_vector(item)


def load(path, limit):
    rows, labels, appeared, families = [], [], [], []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if len(labels) >= limit:
                break
            try:
                item = json.loads(line)
                label = int(item["label"])
            except (ValueError, KeyError, TypeError):
                continue
            if label not in (0, 1):
                # EMBER marks unknown provenance with -1; a sample whose label
                # is unknown is not benign and must not train the benign side.
                continue
            rows.append(np.asarray(vector(item), dtype=np.float32))
            labels.append(label)
            appeared.append(int(str(item.get("appeared", "0")).replace("-", "") or 0))
            families.append(str(item.get("avclass", "") or ""))
    return (np.asarray(rows, dtype=np.float32), np.asarray(labels, dtype=np.float32),
            np.asarray(appeared, dtype=np.int64), np.asarray(families))


def auc_manual(labels, probability):
    """Rank-based AUC that tolerates the odd shape the loader can produce."""
    labels = np.ravel(labels)
    probability = np.ravel(probability)
    order = np.argsort(probability)
    ranks = np.empty(len(probability), dtype=np.float64)
    ranks[order] = np.arange(1, len(probability) + 1)
    positive = labels == 1
    n_positive = positive.sum()
    n_negative = len(labels) - n_positive
    if n_positive == 0 or n_negative == 0:
        return float("nan")
    return float((ranks[positive].sum() - n_positive * (n_positive + 1) / 2) / (n_positive * n_negative))


def benchmark(name, train_mask, test_mask, x, y, iterations):
    model = HistGradientBoostingClassifier(max_iter=iterations, learning_rate=0.1,
                                           max_leaf_nodes=31, early_stopping=True, random_state=11)
    model.fit(x[train_mask], y[train_mask])
    probability = np.ravel(model.predict_proba(x[test_mask])[:, 1])
    labels = np.ravel(y[test_mask])
    auc = auc_manual(labels, probability)
    benign = probability[labels == 0]
    malicious = probability[labels == 1]
    print("%s: train %d, test %d (%.1f%% malicious), AUC %.4f"
          % (name, train_mask.sum(), test_mask.sum(), 100 * labels.mean(), auc))
    zero_fp = float(benign.max()) + 1e-6
    print("   FPR 0 (threshold above every benign: %.4f) -> recall %.1f%%"
          % (zero_fp, 100 * (malicious >= zero_fp).mean()))
    for fpr in (0.01, 0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        print("   FPR %.4f -> recall %.1f%% (threshold %.4f)"
              % (fpr, 100 * (malicious >= threshold).mean(), threshold))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--limit", type=int, default=150000)
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()

    x, y, appeared, families = load(args.jsonl, args.limit)
    print("samples %d, features %d, malicious %.1f%%" % (len(x), x.shape[1], 100 * y.mean()))

    # Time split: the newest third is what an analyst would not have seen.
    order = np.argsort(appeared)
    cut = int(len(order) * 0.66)
    train_mask = np.zeros(len(x), dtype=bool)
    train_mask[order[:cut]] = True
    test_mask = ~train_mask
    benchmark("time split", train_mask, test_mask, x, y, args.iterations)

    # Family split: hold out every fourth family among the malicious samples.
    malware_families = sorted({f for f, label in zip(families, y) if label == 1 and f})
    held = {family for index, family in enumerate(malware_families) if index % 4 == 0}
    is_held = np.array([family in held for family in families])
    train_mask = ~is_held
    test_mask = is_held & (y == 1)
    if test_mask.sum() > 100:
        print("held-out families: %d, malicious samples %d" % (len(held), int(test_mask.sum())))
        model = HistGradientBoostingClassifier(max_iter=args.iterations, learning_rate=0.1,
                                               max_leaf_nodes=31, early_stopping=True, random_state=11)
        model.fit(x[train_mask], y[train_mask])
        probability = model.predict_proba(x[test_mask])[:, 1]
        benign = model.predict_proba(x[~is_held & (y == 0), ])[:, 1]
        zero_fp = float(benign.max()) + 1e-6
        print("   held-out family recall at FPR 0 (threshold %.4f): %.1f%%"
              % (zero_fp, 100 * (probability >= zero_fp).mean()))
        for fpr in (0.01, 0.001, 0.0001):
            threshold = np.quantile(benign, 1 - fpr)
            print("   held-out family recall at FPR %.4f: %.1f%% (threshold %.4f)"
                  % (fpr, 100 * (probability >= threshold).mean(), threshold))


if __name__ == "__main__":
    sys.exit(main())
