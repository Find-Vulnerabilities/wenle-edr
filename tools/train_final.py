#!/usr/bin/env python3
"""The measurement the objective asks for: unseen benign work, unseen techniques.

Takes the verified technique corpus (one technique in five held out) and a fresh
benign collection (twenty percent held out), trains on the rest, and reports the
two numbers: false positives on benign work the model has not seen, and recall on
techniques it has not seen.

Usage: python tools/train_final.py --techniques A.npz --benign B.npz --out model.bin
"""
import argparse
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from train_behaviour import GRU, export, scores_of, train  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--techniques", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()

    techniques = np.load(args.techniques, allow_pickle=False)
    benign = np.load(args.benign, allow_pickle=False)
    x, y, fam = techniques["x"], techniques["y"], techniques["family"]
    names = sorted({str(f) for f in fam if str(f).startswith("T")})
    held = set(names[::5])
    mask = np.array([str(f) in held for f in fam]) & (y == 1)

    bx = benign["x"]
    order = np.random.default_rng(13).permutation(len(bx))
    cut = int(len(bx) * 0.8)
    benign_train, benign_test = bx[order[:cut]], bx[order[cut:]]

    train_x = np.concatenate([x[~mask], benign_train])
    train_y = np.concatenate([y[~mask], np.zeros(len(benign_train), np.float32)])
    print("training: %d malicious, %d benign; held-out %d techniques and %d benign stories"
          % (int(train_y.sum()), int((train_y == 0).sum()), len(held), len(benign_test)))
    model = GRU()
    train(model, list(train_x), list(train_y), args.epochs, class_weight=4.0)
    export(model, args.out)

    test_scores = scores_of(model, list(benign_test))
    technique_scores = scores_of(model, list(x[mask]))
    held_fam = fam[mask]
    for threshold in (0.99, 0.995, 0.996):
        false_positives = int((test_scores >= threshold).sum())
        counts = {}
        for family, score in zip(held_fam, technique_scores):
            if score >= threshold:
                counts[str(family)] = counts.get(str(family), 0) + 1
        caught = len(counts)
        confirmed = sum(1 for value in counts.values() if value >= 2)
        print("threshold %.3f: benign %d/%d  techniques %d/%d (two stories %d)"
              % (threshold, false_positives, len(test_scores), caught, len(held), confirmed))


if __name__ == "__main__":
    main()
