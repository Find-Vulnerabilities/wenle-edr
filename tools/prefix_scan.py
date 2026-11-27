#!/usr/bin/env python3
"""Does the story's *maximum* score beat its final score?

A dropper's malicious moment is the write and the start; everything after it --
the child's ordinary output, the cleanup -- dilutes the hidden state. The
training label covers the whole story, so the model is trained to end at the
label, but at inference the interesting score may be the one taken at the
moment the act happened.

This scans prefixes of each story (the last eight events, the last sixteen, and
so on), scores each, and compares two decision rules at the same false-positive
rate: the score at the end, and the maximum over the prefixes.

Usage:
    python tools/prefix_scan.py --corpus target/corpus-balanced.npz \
        --model target/behaviour-v2.bin [--fpr 0.001]
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from score_log import load_model  # noqa: E402
from train_behaviour import LENGTH, metrics, threshold_at  # noqa: E402


def prefix_batch(x, length):
    """Keep the last `length` events of every story, padding at the front."""
    out = np.zeros_like(x)
    out[:, LENGTH - length:] = x[:, LENGTH - length:]
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--fpr", type=float, default=0.001)
    args = parser.parse_args()

    stored = np.load(args.corpus, allow_pickle=False)
    x = stored["x"]
    y = stored["y"]
    model = load_model(args.model)
    print("stories %d, malicious %d" % (len(x), int(sum(y))))

    lengths = [8, 16, 24, 32, 40, 48, 56, 64]
    per_length = {}
    for length in lengths:
        probabilities, _ = model.forward(prefix_batch(x, length))
        scores = probabilities[:, 0]
        per_length[length] = scores
        threshold = threshold_at(scores, y, args.fpr)
        result = metrics(scores, y, threshold)
        print("prefix %2d: recall %.3f fp %.4f auc %.3f threshold %.4f"
              % (length, result["recall"], result["false_positive"], result["auc"], threshold))

    combined = np.max(np.stack([per_length[length] for length in lengths]), axis=0)
    threshold = threshold_at(combined, y, args.fpr)
    result = metrics(combined, y, threshold)
    print("max over prefixes: recall %.3f fp %.4f auc %.3f threshold %.4f"
          % (result["recall"], result["false_positive"], result["auc"], threshold))
    return 0


if __name__ == "__main__":
    sys.exit(main())
