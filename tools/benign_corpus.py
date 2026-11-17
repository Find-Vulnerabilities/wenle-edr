#!/usr/bin/env python3
"""Turn a log with no labels into benign stories, the same shape prepare makes.

Usage: python tools/benign_corpus.py --log X --out Y [--max 40000]
"""
import argparse
import io
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from train_behaviour import LENGTH, WIDTH  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max", type=int, default=40000)
    args = parser.parse_args()

    stories = {}
    with io.open(args.log, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 3 + WIDTH:
                continue
            try:
                pid = int(fields[0])
                features = [float(value) for value in fields[3:3 + WIDTH]]
            except ValueError:
                continue
            story = stories.setdefault(pid, [])
            story.append(features)
            if len(story) > LENGTH:
                story.pop(0)

    sequences = []
    for story in stories.values():
        if len(story) < 4:
            continue
        story = story[-LENGTH:]
        padded = np.zeros((LENGTH, WIDTH), np.float32)
        padded[LENGTH - len(story):] = np.asarray(story, np.float32)
        sequences.append(padded)
        if len(sequences) >= args.max:
            break

    x = np.stack(sequences)
    y = np.zeros(len(x), np.float32)
    np.savez_compressed(args.out, x=x, y=y)
    print("benign stories %d, shape %s" % (len(x), x.shape))


if __name__ == "__main__":
    main()
