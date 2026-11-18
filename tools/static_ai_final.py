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
    features = []
    features.extend((item.get("histogram", []) + [0] * 256)[:256])
    features.extend((item.get("byteentropy", []) + [0] * 256)[:256])
    general = item.get("general", {}) or {}
    features.extend(float(general.get(key, 0) or 0) for key in GENERAL)
    header = item.get("header", {}) or {}
    features.extend(float(header.get(key, 0) or 0) for key in HEADER)
    sections = item.get("section", {}) or {}
    features.append(float(sections.get("count", 0) or 0))
    entropies = sections.get("entropy") or []
    features.extend([float(np.mean(entropies)), float(np.max(entropies)), float(np.min(entropies))] if entropies else [0.0, 0.0, 0.0])
    imports = item.get("imports", {}) or {}
    features.append(float(len(imports)))
    features.append(float(sum(len(f) for f in imports.values() if isinstance(f, list))))
    strings = item.get("strings", {}) or {}
    features.extend(float(strings.get(key, 0) or 0) for key in ("numstrings", "avlength", "printables", "urls", "paths"))
    return features


def load(path, limit):
    rows, labels, appeared, families = [], [], [], []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if len(labels) >= limit:
                break
            try:
                item = json.loads(line)
                label = int(item["label"])
            except (ValueError, KeyError):
                continue
            rows.append(vector(item))
            labels.append(label)
            appeared.append(int(str(item.get("appeared", "0")).replace("-", "") or 0))
            families.append(str(item.get("avclass", "") or ""))
    return (np.asarray(rows, dtype=np.float32), np.asarray(labels, dtype=np.float32),
            np.asarray(appeared, dtype=np.int64), np.asarray(families))


def benchmark(name, train_mask, test_mask, x, y, iterations):
    model = HistGradientBoostingClassifier(max_iter=iterations, learning_rate=0.1,
                                           max_leaf_nodes=31, early_stopping=True, random_state=11)
    model.fit(x[train_mask], y[train_mask])
    probability = model.predict_proba(x[test_mask])[:, 1]
    labels = y[test_mask]
    auc = roc_auc_score(labels, probability)
    benign = probability[labels == 0]
    malicious = probability[labels == 1]
    print("%s: train %d, test %d (%.1f%% malicious), AUC %.4f"
          % (name, train_mask.sum(), test_mask.sum(), 100 * labels.mean(), auc))
    for fpr in (0.001, 0.0001):
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
        for fpr in (0.001, 0.0001):
            threshold = np.quantile(benign, 1 - fpr)
            print("   held-out family recall at FPR %.4f: %.1f%% (threshold %.4f)"
                  % (fpr, 100 * (probability >= threshold).mean(), threshold))


if __name__ == "__main__":
    sys.exit(main())
