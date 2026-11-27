#!/usr/bin/env python3
"""Per-language recall with every language in training.

Holding a language out entirely answers a question about transfer, not about
the product: the shipped model trains on all seven languages. This measures the
product's question -- of the files of each language it has never seen, how many
does it catch at a fixed false-positive rate -- with a stratified split so every
language appears in both halves.

Usage: python tools/script_perlanguage.py --scripts C:\\...\\script-ai
"""
import argparse
import os
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

LANGUAGES = {
    "batch": (".bat", ".cmd"),
    "powershell": (".ps1", ".psm1"),
    "python": (".py",),
    "javascript": (".js",),
    "vbscript": (".vbs",),
    "hta": (".hta",),
}


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
    print("rows:", len(rows), flush=True)

    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    languages = np.asarray([ext for _, ext, _ in rows])
    matrix = vectorize(rows)

    rng = np.random.default_rng(11)
    train = np.zeros(len(rows), dtype=bool)
    for group in LANGUAGES.values():
        index = np.flatnonzero(np.isin(languages, group))
        if len(index) == 0:
            continue
        chosen = rng.permutation(index)[: int(len(index) * 0.8)]
        train[chosen] = True

    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=800, learning_rate=0.05,
        num_leaves=127, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix[train], labels[train])
    probability = model.predict_proba(matrix[~train])[:, 1]
    truth = labels[~train]
    test_languages = languages[~train]

    benign = probability[truth == 0]
    thresholds = {value: float(np.quantile(benign, 1.0 - value)) for value in (0.01, 0.001)}
    for name, group in LANGUAGES.items():
        mask = np.isin(test_languages, group) & (truth == 1)
        if mask.sum() == 0:
            continue
        line = "%-12s files %4d" % (name, int(mask.sum()))
        for value in (0.01, 0.001):
            recall = float((probability[mask] > thresholds[value]).mean())
            line += "  FPR %.1f%% -> %.1f%%" % (100 * value, 100 * recall)
        print(line, flush=True)
    overall = float((probability[truth == 1] > thresholds[0.001]).mean())
    print("overall @0.1%% FPR: %.1f%%" % (100 * overall))


if __name__ == "__main__":
    main()
