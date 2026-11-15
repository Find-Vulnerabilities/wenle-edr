#!/usr/bin/env python3
"""Train on public attacks plus held-out host benign, and report what transfers.

Three numbers, and the third is the one that decides anything:

1. Training separation on the public captures (does the model learn them at all).
2. False positives on host benign stories the training never saw.
3. Recall on the host families -- behaviours in our telemetry that the public
   captures do not contain. This is the "unknown threat" number.

Usage:
    python tools/train_mixed.py --public target/sysmon-all.npz \
        --corpus target/corpus-balanced.npz --out target/mixed.bin [--epochs 30]
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_behaviour import GRU, metrics, scores_of, threshold_at, train  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--public", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--fpr", type=float, default=0.001)
    parser.add_argument("--holdout", type=float, default=0.25)
    args = parser.parse_args()

    public = np.load(args.public, allow_pickle=False)
    attack_x = public["x"]
    print("public attack sequences: %d" % len(attack_x))

    corpus = np.load(args.corpus, allow_pickle=False)
    x = corpus["x"]
    y = corpus["y"]
    families = corpus["family"]
    benign_x = x[y == 0]
    attack_host_x = x[y == 1]
    attack_host_families = families[y == 1]

    # A quarter of the benign stories are never trained on: false positives have
    # to be counted on stories the model has not memorised.
    rng = np.random.default_rng(11)
    order = rng.permutation(len(benign_x))
    cut = int(len(benign_x) * (1 - args.holdout))
    train_benign = benign_x[order[:cut]]
    test_benign = benign_x[order[cut:]]
    print("train benign %d, held-out benign %d, host families %d"
          % (len(train_benign), len(test_benign), len(attack_host_x)))

    train_x = np.concatenate([attack_x, train_benign])
    train_y = np.concatenate([np.ones(len(attack_x), dtype=np.float32),
                              np.zeros(len(train_benign), dtype=np.float32)])
    model = GRU()
    train(model, list(train_x), list(train_y), args.epochs, class_weight=4.0)

    # Threshold from the held-out benign tail: the operating point a user would
    # meet, not a number chosen after seeing the test set.
    benign_scores = scores_of(model, list(test_benign))
    threshold = float(np.quantile(benign_scores, 1.0 - args.fpr))
    print("held-out benign: p99 %.3f p99.9 %.3f max %.3f -> threshold %.4f"
          % (np.quantile(benign_scores, 0.99), np.quantile(benign_scores, 0.999),
             benign_scores.max(), threshold))

    scores = scores_of(model, list(attack_host_x))
    print("transfer to host families (threshold %.4f):" % threshold)
    rows = []
    for family in sorted(set(attack_host_families.tolist())):
        mask = attack_host_families == family
        recall = float((scores[mask] > threshold).mean())
        rows.append((family, recall, int(mask.sum())))
    for family, recall, count in rows:
        print("  %-22s recall %.3f (n=%d)" % (family, recall, count))
    overall = float((scores > threshold).mean())
    print("transfer overall recall %.3f" % overall)

    from train_behaviour import export
    export(model, args.out)
    print("weights written to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
