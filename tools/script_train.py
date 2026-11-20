#!/usr/bin/env python3
"""Train one LightGBM over every script language, and judge it honestly.

Three things the numbers must show:

  * a random split, which is the optimistic bound;
  * a language-held-out split, where a whole language is absent from training
    and appears only in the test set -- this is what "one model for every
    language" has to mean;
  * the false-positive rate on benign scripts, because a script model that
    flags administrators' scripts is worse than no model.

Usage: python tools/script_train.py --scripts C:\\...\\script-ai
"""
import argparse
import glob
import io
import json
import os
import random
import sys

import lightgbm as lgb
import numpy as np
import pyarrow.parquet as pq
from scipy import sparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_ai import features


def read_parquet_malicious(root, limit):
    rows = []
    for path in sorted(glob.glob(os.path.join(root, "*.parquet"))):
        try:
            reader = pq.ParquetFile(path)
        except Exception:
            continue
        try:
            batches = reader.iter_batches(batch_size=128, columns=["content", "label"])
            for batch in batches:
                for item in batch.to_pylist():
                    content = item.get("content")
                    label = item.get("label")
                    if isinstance(content, bytes):
                        content = content.decode("utf-8", "replace")
                    if not isinstance(content, str) or label != 1:
                        continue
                    rows.append((content.encode("utf-8", "replace")[:200000], ".ps1", 1))
                    if len(rows) >= limit:
                        return rows
        except Exception:
            continue
    return rows


def read_directory(path, label, extension=None, limit=100000):
    rows = []
    for entry in sorted(os.listdir(path)):
        full = os.path.join(path, entry)
        if not os.path.isfile(full):
            continue
        if extension and not entry.lower().endswith(extension):
            continue
        try:
            with open(full, "rb") as handle:
                data = handle.read(2 * 1024 * 1024)
        except OSError:
            continue
        rows.append((data, os.path.splitext(entry)[1].lower(), label))
        if len(rows) >= limit:
            break
    return rows


def read_benign_from_disk(limit_per_extension):
    roots = [r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules",
             r"C:\Program Files\WindowsApps" if False else r"C:\Program Files"]
    rows = []
    extensions = {".ps1": 0, ".psm1": 0, ".js": 0, ".vbs": 0, ".bat": 0, ".py": 0, ".cmd": 0}
    for root in roots:
        for current, _, files in os.walk(root):
            if len(rows) >= sum(limit_per_extension.values()):
                break
            for name in files:
                extension = os.path.splitext(name)[1].lower()
                if extension not in extensions or extensions[extension] >= limit_per_extension.get(extension, 0):
                    continue
                full = os.path.join(current, name)
                try:
                    if os.path.getsize(full) > 1024 * 1024:
                        continue
                    with open(full, "rb") as handle:
                        data = handle.read()
                except OSError:
                    continue
                extensions[extension] += 1
                rows.append((data, extension, 0))
    return rows


def vectorize(rows):
    dense = []
    sparse_rows = []
    sparse_cols = []
    sparse_values = []
    for index, (data, _, _) in enumerate(rows):
        d, grams = features(data)
        dense.append(d)
        for column, count in grams.items():
            sparse_rows.append(index)
            sparse_cols.append(column)
            sparse_values.append(float(count))
    dense = np.asarray(dense, dtype=np.float32)
    hashed = sparse.csr_matrix(
        (sparse_values, (sparse_rows, sparse_cols)),
        shape=(len(rows), 1 << 18),
        dtype=np.float32,
    )
    return sparse.hstack([sparse.csr_matrix(dense), hashed]).tocsr()


def evaluate(name, matrix, labels, languages, train_mask, test_mask, trees=400):
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=trees, learning_rate=0.05,
        num_leaves=63, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix[train_mask], labels[train_mask])
    probability = model.predict_proba(matrix[test_mask])[:, 1]
    truth = labels[test_mask]
    benign = probability[truth == 0]
    malicious = probability[truth == 1]
    print("%s: train %d test %d (%.1f%% malicious), languages %s"
          % (name, int(train_mask.sum()), int(test_mask.sum()),
             100 * truth.mean(), sorted(set(languages[test_mask].tolist()))), flush=True)
    for fpr in (0.01, 0.001, 0.0001):
        if len(benign) == 0:
            print("   no benign in test; recall at best threshold %.1f%%"
                  % (100 * (malicious >= 0.5).mean()))
            break
        threshold = np.quantile(benign, 1 - fpr)
        print("   FPR %.4f -> recall %.1f%% (threshold %.4f)"
              % (fpr, 100 * (malicious >= threshold).mean(), threshold), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--malicious-limit", type=int, default=6000)
    parser.add_argument("--benign-per-extension", type=int, default=250)
    args = parser.parse_args()

    rows = []
    rows += [(d, e, 1) for d, e, l in read_parquet_malicious(
        args.scripts, args.malicious_limit)]
    rows += read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: args.benign_per_extension
                                   for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})
    print("rows: %d (malicious %d)" % (len(rows), sum(label for _, _, label in rows)), flush=True)

    matrix = vectorize(rows)
    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    languages = np.asarray([extension for _, extension, _ in rows])
    print("matrix: %s" % (matrix.shape,), flush=True)

    index = np.arange(len(rows))
    random.Random(11).shuffle(index.tolist())
    rng = np.random.default_rng(11)
    order = rng.permutation(len(rows))
    cut = int(len(rows) * 0.7)
    train = np.zeros(len(rows), dtype=bool)
    train[order[:cut]] = True
    evaluate("random split", matrix, labels, languages, train, ~train)

    for held in ((".bat", ".cmd"), (".py",)):
        test = np.isin(languages, held)
        train = ~test
        if test.sum() > 20:
            evaluate("language held out %s" % "/".join(held), matrix, labels, languages, train, test)


if __name__ == "__main__":
    sys.exit(main())
