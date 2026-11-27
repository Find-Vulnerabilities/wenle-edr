#!/usr/bin/env python3
"""A first static-AI number on real labelled PEs, without Elastic's package.

The EMBER JSONL carries the raw PE description rather than the 2,381-vector:
histogram and byteentropy (256 each), general counts, header, sections, imports,
exports, strings. This reduces them to a few hundred numbers, trains a histogram
gradient-boosting classifier on a sample, and reports where the operating point
sits -- recall at a false-positive rate a product could carry.

Usage: python tools/static_ai_pe.py --jsonl X --limit 100000
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
SECTION = ["count"]


def vector(item):
    features = []
    histogram = item.get("histogram", [])
    byteentropy = item.get("byteentropy", [])
    features.extend((histogram + [0] * 256)[:256])
    features.extend((byteentropy + [0] * 256)[:256])
    general = item.get("general", {}) or {}
    features.extend(float(general.get(key, 0) or 0) for key in GENERAL)
    header = item.get("header", {}) or {}
    features.extend(float(header.get(key, 0) or 0) for key in HEADER)
    sections = item.get("section", {}) or {}
    features.append(float(sections.get("count", 0) or 0))
    entropies = sections.get("entropy") or []
    if entropies:
        features.extend([float(np.mean(entropies)), float(np.max(entropies)), float(np.min(entropies))])
    else:
        features.extend([0.0, 0.0, 0.0])
    imports = item.get("imports", {}) or {}
    features.append(float(len(imports)))
    features.append(float(sum(len(functions) for functions in imports.values() if isinstance(functions, list))))
    strings = item.get("strings", {}) or {}
    features.extend(float(strings.get(key, 0) or 0) for key in ("numstrings", "avlength", "printables", "urls", "paths"))
    return features


def load(path, limit):
    rows = []
    labels = []
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
    return np.asarray(rows, dtype=np.float32), np.asarray(labels, dtype=np.float32)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--limit", type=int, default=100000)
    parser.add_argument("--iterations", type=int, default=150)
    args = parser.parse_args()

    x, y = load(args.jsonl, args.limit)
    print("samples %d, features %d, malicious %.1f%%" % (len(x), x.shape[1], 100 * y.mean()))
    order = np.random.default_rng(11).permutation(len(x))
    cut = int(len(x) * 0.8)
    train, test = order[:cut], order[cut:]
    model = HistGradientBoostingClassifier(max_iter=args.iterations, learning_rate=0.1,
                                           max_leaf_nodes=31, early_stopping=True, random_state=11)
    model.fit(x[train], y[train])
    probability = model.predict_proba(x[test])[:, 1]
    auc = roc_auc_score(y[test], probability)
    benign = probability[y[test] == 0]
    malicious = probability[y[test] == 1]
    for fpr in (0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        print("FPR %.4f -> recall %.1f%% (threshold %.4f)"
              % (fpr, 100 * (malicious >= threshold).mean(), threshold))
    print("AUC %.4f on %d held-out samples" % (auc, len(test)))


if __name__ == "__main__":
    sys.exit(main())
