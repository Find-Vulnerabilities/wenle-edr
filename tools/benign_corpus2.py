#!/usr/bin/env python3
"""Turn a log with no labels into benign stories, one per contiguous segment.

A pid's events are a story only while they are close together; the same pid an
hour later is a different story. The first version of this kept one story per
pid and produced forty-seven stories from a two-hundred-megabyte log, which is
not a sample of ordinary work.

Usage: python tools/benign_corpus.py --log X --out Y [--max 20000]
"""
import argparse
import io
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from train_behaviour import LENGTH, WIDTH  # noqa: E402

GAP_MICROS = 120_000_000  # two minutes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max", type=int, default=20000)
    args = parser.parse_args()

    current = {}
    completed = []
    with io.open(args.log, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 3 + WIDTH:
                continue
            try:
                pid = int(fields[0])
                stamp = int(fields[2])
                features = [float(value) for value in fields[3:3 + WIDTH]]
            except ValueError:
                continue
            story = current.get(pid)
            if story is None or stamp - story["last"] > GAP_MICROS or len(story["events"]) >= LENGTH:
                if story is not None and len(story["events"]) >= 4:
                    completed.append(story["events"])
                story = {"last": stamp, "events": []}
                current[pid] = story
            story["last"] = stamp
            story["events"].append(features)
        for story in current.values():
            if len(story["events"]) >= 4:
                completed.append(story["events"])

    sequences = []
    for events in completed:
        events = events[-LENGTH:]
        padded = np.zeros((LENGTH, WIDTH), np.float32)
        padded[LENGTH - len(events):] = np.asarray(events, np.float32)
        sequences.append(padded)
        if len(sequences) >= args.max:
            break

    x = np.stack(sequences)
    np.savez_compressed(args.out, x=x, y=np.zeros(len(x), np.float32))
    print("benign stories %d, shape %s" % (len(x), x.shape))


if __name__ == "__main__":
    main()
