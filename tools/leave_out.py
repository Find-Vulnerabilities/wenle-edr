#!/usr/bin/env python3
"""Train on families and most techniques, and test on techniques never seen.

The question is not whether the model can separate the data it trained on. It is
whether a behaviour it has not seen is scored as malicious at the same operating
point where ordinary work is not. The split is by technique, so a whole way of
doing something is absent from training.

Usage:
    python tools/leave_out.py --host target/corpus-night.npz \
        --guest target/vm-corpus.npz --out target/loo.bin [--hold 8]
"""

import argparse
import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_behaviour import GRU, export, scores_of, threshold_at, train  # noqa: E402


def split_by_family(x, y, families, hold_families):
    hold = np.array([str(f) in hold_families for f in families])
    return x[~hold], y[~hold], x[hold], y[hold]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--guest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=25)
    parser.add_argument("--hold", type=int, default=8)
    parser.add_argument("--fpr", type=float, default=0.001)
    args = parser.parse_args()

    host = np.load(args.host, allow_pickle=False)
    guest = np.load(args.guest, allow_pickle=False)

    # Techniques are the families in the guest corpus whose names start with T.
    techniques = sorted({str(f) for f in guest["family"] if str(f).startswith("T")})
    if not techniques:
        print("no technique families in the guest corpus")
        return 1
    held = set(techniques[:: max(1, len(techniques) // args.hold)])
    print("techniques %d, held out %d: %s" % (len(techniques), len(held), ", ".join(sorted(held))))

    train_x, train_y, held_x, held_y = split_by_family(
        guest["x"], guest["y"], guest["family"], held
    )
    print("guest: train %d (malicious %d), held-out %d (malicious %d)"
          % (len(train_x), int(train_y.sum()), len(held_x), int(held_y.sum())))

    x = np.concatenate([host["x"], train_x])
    y = np.concatenate([host["y"], train_y])
    benign = x[y == 0]
    rng = np.random.default_rng(9)
    if len(benign) > 20000:
        benign = benign[rng.choice(len(benign), 20000, replace=False)]
    attack = x[y == 1]
    print("training on %d malicious, %d benign" % (len(attack), len(benign)))

    mixed_x = np.concatenate([attack, benign])
    mixed_y = np.concatenate([np.ones(len(attack), np.float32), np.zeros(len(benign), np.float32)])
    model = GRU()
    train(model, list(mixed_x), list(mixed_y), args.epochs, class_weight=4.0)
    export(model, args.out)

    # The threshold is the benign tail the machine actually produces: the host
    # corpus's benign stories, never the held-out techniques.
    host_benign = host["x"][host["y"] == 0]
    host_scores = scores_of(model, list(host_benign))
    threshold = threshold_at(host_scores, np.zeros(len(host_benign), np.float32), args.fpr)
    print("host benign: p99.9 %.3f max %.3f -> threshold %.4f"
          % (np.quantile(host_scores, 0.999), host_scores.max(), threshold))

    held_scores = scores_of(model, list(held_x[held_y == 1]))
    held_families = guest["family"][np.array([str(f) in held for f in guest["family"]])][held_y == 1]
    caught = sorted({str(f) for f, s in zip(held_families, held_scores) if s >= threshold})
    print("held-out techniques caught: %d of %d families, %.1f%% of stories"
          % (len(caught), len(set(str(f) for f in held_families)), 100.0 * (held_scores >= threshold).mean()))
    print("  caught:", ", ".join(caught) if caught else "(none)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
