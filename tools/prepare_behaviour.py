#!/usr/bin/env python3
"""Turn the behaviour log into padded sequences, once.

The trainer used to parse three hundred thousand lines and rebuild the
sequences for every leave-one-family-out run. That is the same work repeated
twelve times, and it is the reason an evaluation took longer than the collection
that fed it.

This writes one `.npz` -- padded sequences, labels, families -- and the trainer
reads it. Benign sequences are subsampled: the machine produces far more of them
than the model needs, and a training set that is 99% background teaches the
model to say "benign" and nothing else.

Usage:
    python tools/prepare_behaviour.py --log <behaviour.log> --labels <labels.csv> \\
        --out corpus.npz [--max-benign 3000]
"""

import argparse
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])

from train_behaviour import (  # noqa: E402
    LENGTH,
    WIDTH,
    build_sequences,
    load_events,
    load_windows,
    pad,
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--log-extra", default=None, help="an older log to read first")
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-benign", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=5)
    parser.add_argument("--descendants", action="store_true", help="label the process tree, not just the root")
    args = parser.parse_args()

    events = []
    if args.log_extra:
        events.extend(load_events(args.log_extra))
    events.extend(load_events(args.log))
    windows = load_windows(args.labels)
    sequences = build_sequences(events, windows, descendants=args.descendants)
    print("events %d, windows %d, sequences %d" % (len(events), len(windows), len(sequences)))

    rng = np.random.default_rng(args.seed)
    malicious = [item for item in sequences if item[0] == "malicious"]
    benign = [item for item in sequences if item[0] != "malicious"]
    if len(benign) > args.max_benign:
        # Balanced by the process image the story belongs to, not sampled at
        # random: a random draw of this machine's log is mostly the shell that
        # runs the harness, and a model calibrated on that has never seen a
        # browser, a package manager or a build. The image class is the last
        # event's image feature, which is class/8; round it back.
        groups = {}
        for index in range(len(benign)):
            image = int(round(benign[index][2][-1][33] * 8))
            groups.setdefault(image, []).append(index)
        share = max(1, args.max_benign // len(groups))
        picked = []
        for image in sorted(groups):
            members = groups[image]
            rng.shuffle(members)
            picked.extend(members[:share])
        remaining = args.max_benign - len(picked)
        if remaining > 0:
            taken = set(picked)
            leftovers = [index for index in range(len(benign)) if index not in taken]
            picked.extend(rng.choice(leftovers, size=min(remaining, len(leftovers)), replace=False).tolist())
        benign = [benign[index] for index in sorted(picked)]
        counts = {}
        for item in benign:
            image = int(round(item[2][-1][33] * 8))
            counts[image] = counts.get(image, 0) + 1
        print("benign by image class: %s" % sorted(counts.items()))
    print("keeping %d malicious and %d benign" % (len(malicious), len(benign)))

    items = malicious + benign
    x = np.stack([pad(item[2]) for item in items])
    y = np.array([1.0 if item[0] == "malicious" else 0.0 for item in items], dtype=np.float32)
    family = np.array([item[1] for item in items])
    np.savez_compressed(args.out, x=x, y=y, family=family)
    print("wrote %s: x %s, %d malicious, %d benign" % (args.out, x.shape, len(malicious), len(benign)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
