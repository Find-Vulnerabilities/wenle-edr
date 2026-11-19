#!/usr/bin/env python3
"""A model whose features the Rust scanner can compute without a PE library.

The 537-vector needed hashed import names and string statistics, which is real
work to reproduce exactly. This one is 521 numbers that come straight out of the
bytes and the headers: byte histogram, byte entropy, file and virtual size, four
header fields, section count and the mean, maximum and minimum section entropy.

If this loses little against the 537-vector, it is the one to port: a feature the
Rust side computes identically is worth more than a feature that is theoretically
better and cannot be reproduced.

Usage: python tools/static_ai_port.py --jsonl combined3.jsonl
"""
import argparse
import io
import json
import os
import sys

import lightgbm as lgb
import numpy as np


def vector(item):
    features = []
    features.extend((item.get("histogram", []) + [0] * 256)[:256])
    features.extend((item.get("byteentropy", []) + [0] * 256)[:256])
    general = item.get("general", {}) or {}
    features.append(float(general.get("size", 0) or 0))
    features.append(float(general.get("vsize", 0) or 0))
    header = item.get("header", {}) or {}
    for key in ("machine", "subsystem", "characteristics", "dll_characteristics"):
        features.append(float(header.get(key, 0) or 0))
    section = item.get("section", {}) or {}
    features.append(float(section.get("count", 0) or 0))
    entropies = section.get("entropy") or []
    features.extend(
        [float(np.mean(entropies)), float(np.max(entropies)), float(np.min(entropies))]
        if entropies
        else [0.0, 0.0, 0.0]
    )
    return features


def read_file(path, limit):
    rows, labels, families = [], [], []
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
            families.append(str(item.get("avclass", "") or ""))
    return np.stack(rows), np.asarray(labels, dtype=np.float32), np.asarray(families)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--jsonl", required=True)
    parser.add_argument("--limit", type=int, default=230000)
    parser.add_argument("--trees", type=int, default=500)
    parser.add_argument("--leaves", type=int, default=255)
    args = parser.parse_args()

    x, y, families = read_file(args.jsonl, args.limit)
    print("samples %d, features %d, malicious %.1f%%"
          % (len(x), x.shape[1], 100 * y.mean()), flush=True)

    malware = sorted({f for f, label in zip(families, y) if label == 1 and f})
    held = {family for index, family in enumerate(malware) if index % 4 == 0}
    is_held = np.array([family in held for family in families])
    print("held-out families %d, samples %d" % (len(held), int(is_held.sum())), flush=True)

    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=args.trees, learning_rate=0.05,
        num_leaves=args.leaves, min_child_samples=20, feature_fraction=0.4,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(x[~is_held], y[~is_held])
    out = os.path.join(os.path.dirname(__file__), "..", "target", "static_port.txt")
    model.booster_.save_model(out)
    print("saved", out, flush=True)

    benign = model.predict_proba(x[(~is_held) & (y == 0)])[:, 1]
    if len(benign) > 60000:
        benign = np.random.default_rng(3).choice(benign, 60000, replace=False)
    malicious = model.predict_proba(x[is_held & (y == 1)])[:, 1]
    for fpr in (0.01, 0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        print("   FPR %.4f -> recall %.1f%% (threshold %.4f)"
              % (fpr, 100 * (malicious >= threshold).mean(), threshold), flush=True)


if __name__ == "__main__":
    sys.exit(main())
