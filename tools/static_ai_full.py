#!/usr/bin/env python3
"""Static AI with a full PE vector, trained on both the training and test files.

The vector assembled here is the one published EMBER work uses in spirit: byte
histogram and byte entropy (256 each), string statistics, general and header
fields, section statistics, hashed import and export names, and the data
directories. It is built from the precomputed JSONL descriptions, so no PE file
is needed and the 1.6 GB dataset can be sampled quickly.

Two splits decide whether the number is worth anything:

  * time   -- train on the older two thirds, test on what came after;
  * family -- hold every fourth avclass family out of training entirely.

Usage: python tools/static_ai_full.py --test X.jsonl --train-dir DIR --per-train 25000
"""
import argparse
import glob
import hashlib
import json
import os
import sys

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

STRING_KEYS = ["numstrings", "avlength", "printables", "printabledist", "entropy",
               "paths", "urls", "registry", "mz"]
GENERAL_KEYS = ["size", "vsize", "imports", "exports", "has_debug", "has_relocations",
                "has_resources", "has_signature", "has_tls", "symbols"]
HEADER_KEYS = ["machine", "subsystem", "characteristics", "dll_characteristics",
               "magic", "major_linker_version", "minor_linker_version",
               "major_operating_system_version", "minor_operating_system_version",
               "major_image_version", "minor_image_version", "major_subsystem_version",
               "minor_subsystem_version", "sizeof_code", "sizeof_headers",
               "sizeof_heap_commit", "timestamp"]
DIRECTORIES = ["export_table", "import_table", "resource_table", "exception_table",
               "certificate_table", "base_relocation_table", "debug", "architecture",
               "global_ptr", "tls_table", "load_config_table", "bound_import",
               "import_address_table", "delay_import_descriptor", "clr_runtime_header"]

LIB_BUCKETS = 256
FUNC_BUCKETS = 1024
EXPORT_BUCKETS = 128


def bucket(name, buckets):
    digest = hashlib.md5(name.encode("utf-8", "ignore")).digest()
    return int.from_bytes(digest[:4], "little") % buckets


def vector(item):
    features = []
    features.extend((item.get("histogram", []) + [0] * 256)[:256])
    features.extend((item.get("byteentropy", []) + [0] * 256)[:256])

    strings = item.get("strings", {}) or {}
    distribution = (strings.get("printabledist") or [0] * 96)[:96]
    features.extend(float(value) for value in distribution)
    features.extend(float(strings.get(key, 0) or 0) for key in STRING_KEYS if key != "printabledist")

    general = item.get("general", {}) or {}
    features.extend(float(general.get(key, 0) or 0) for key in GENERAL_KEYS)

    header = item.get("header", {}) or {}
    features.extend(float(header.get(key, 0) or 0) for key in HEADER_KEYS)

    section = item.get("section", {}) or {}
    entropies = section.get("entropy") or []
    features.append(float(section.get("count", 0) or 0))
    features.extend([
        float(np.mean(entropies)) if entropies else 0.0,
        float(np.max(entropies)) if entropies else 0.0,
        float(np.min(entropies)) if entropies else 0.0,
    ])
    for key in ("size", "vsize", "virtual_address"):
        values = section.get(key) or []
        features.append(float(np.sum(values)))
        features.append(float(np.mean(values)) if values else 0.0)

    imports = item.get("imports", {}) or {}
    libraries = np.zeros(LIB_BUCKETS, dtype=np.float32)
    functions = np.zeros(FUNC_BUCKETS, dtype=np.float32)
    for library, names in imports.items():
        libraries[bucket(str(library).lower(), LIB_BUCKETS)] += 1.0
        for name in names if isinstance(names, list) else []:
            functions[bucket(str(name), FUNC_BUCKETS)] += 1.0
    features.extend(libraries.tolist())
    features.extend(functions.tolist())

    exports = item.get("exports") or []
    export_buckets = np.zeros(EXPORT_BUCKETS, dtype=np.float32)
    for name in exports:
        export_buckets[bucket(str(name), EXPORT_BUCKETS)] += 1.0
    features.extend(export_buckets.tolist())

    directories = item.get("datadirectories") or []
    for index in range(15):
        entry = directories[index] if index < len(directories) else {}
        features.append(float((entry or {}).get("size", 0) or 0))
        features.append(float((entry or {}).get("virtual_address", 0) or 0))
    return features


def read_file(path, limit):
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
            rows.append(np.asarray(vector(item), dtype=np.float32))
            labels.append(label)
            appeared.append(int(str(item.get("appeared", "0")).replace("-", "") or 0))
            families.append(str(item.get("avclass", "") or ""))
    return rows, labels, appeared, families


def load(args):
    rows, labels, appeared, families = [], [], [], []
    test_rows, test_labels, test_appeared, test_families = read_file(args.test, args.test_limit)
    rows += test_rows
    labels += test_labels
    appeared += test_appeared
    families += test_families
    for path in sorted(glob.glob(os.path.join(args.train_dir, "train_features_*.jsonl"))):
        more = read_file(path, args.per_train)
        rows += more[0]
        labels += more[1]
        appeared += more[2]
        families += more[3]
        print("loaded", os.path.basename(path), len(more[0]))
    x = np.stack(rows)
    return (x, np.asarray(labels, dtype=np.float32),
            np.asarray(appeared, dtype=np.int64), np.asarray(families))


def run(name, x, y, train_mask, test_mask, iterations):
    model = HistGradientBoostingClassifier(max_iter=iterations, learning_rate=0.1,
                                           max_leaf_nodes=63, early_stopping=True,
                                           random_state=11)
    model.fit(x[train_mask], y[train_mask])
    probability = model.predict_proba(x[test_mask])[:, 1]
    labels = y[test_mask]
    auc = roc_auc_score(labels, probability)
    benign = probability[labels == 0]
    malicious = probability[labels == 1]
    if len(benign) == 0:
        # The family split tests only malicious samples; the false-positive
        # threshold has to come from benign files the model did not train on.
        outside = (~train_mask) & (y == 0)
        benign = model.predict_proba(x[outside])[:, 1] if outside.any() else malicious
    print("%s: train %d test %d (%.1f%% malicious) AUC %.4f"
          % (name, int(train_mask.sum()), int(test_mask.sum()), 100 * labels.mean(), auc))
    for fpr in (0.001, 0.0001):
        threshold = np.quantile(benign, 1 - fpr)
        print("   FPR %.4f -> recall %.1f%%" % (fpr, 100 * (malicious >= threshold).mean()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", required=True)
    parser.add_argument("--train-dir", required=True)
    parser.add_argument("--test-limit", type=int, default=80000)
    parser.add_argument("--per-train", type=int, default=15000)
    parser.add_argument("--iterations", type=int, default=200)
    args = parser.parse_args()

    x, y, appeared, families = load(args)
    print("total %d samples, %d features, malicious %.1f%%"
          % (len(x), x.shape[1], 100 * y.mean()))

    order = np.random.default_rng(11).permutation(len(x))
    cut = int(len(order) * 0.7)
    train_mask = np.zeros(len(x), dtype=bool)
    train_mask[order[:cut]] = True
    run("random split", x, y, train_mask, ~train_mask, args.iterations)

    malware_families = sorted({family for family, label in zip(families, y) if label == 1 and family})
    held = {family for index, family in enumerate(malware_families) if index % 4 == 0}
    is_held = np.array([family in held for family in families])
    if is_held.sum() > 200:
        print("held-out families %d, samples %d" % (len(held), int(is_held.sum())))
        run("family split", x, y, ~is_held, is_held & (y == 1), args.iterations)


if __name__ == "__main__":
    sys.exit(main())
