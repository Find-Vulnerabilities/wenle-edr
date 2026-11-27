#!/usr/bin/env python3
"""One story per time window, all processes in it, to ask whether the signal
exists at all.

The per-process corpus gives a technique's runner only a handful of events. This
builds the other shape: every event inside a labelled window, ordered by time,
padded to the model's sixty-four. If the model separates techniques in this
shape and not in the per-process one, the problem is attribution, not features.

Usage:
    python tools/window_corpus.py --log <behaviour.log> --labels <csv> --out npz
"""
import argparse
import io
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])
from train_behaviour import LENGTH, WIDTH  # noqa: E402


def load_events(path):
    times = []
    rows = []
    with io.open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 3 + WIDTH:
                continue
            try:
                times.append(int(fields[2]))
                rows.append([float(value) for value in fields[3:3 + WIDTH]])
            except ValueError:
                continue
    return np.asarray(times, dtype=np.int64), np.asarray(rows, dtype=np.float32)


def window_story(times, rows, start, end):
    mask = (times >= start) & (times <= end)
    events = rows[mask]
    if len(events) == 0:
        return None
    if len(events) > LENGTH:
        events = events[-LENGTH:]
    story = np.zeros((LENGTH, WIDTH), dtype=np.float32)
    story[LENGTH - len(events):] = events
    return story


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--negatives", type=int, default=4000)
    args = parser.parse_args()

    times, rows = load_events(args.log)
    windows = []
    with io.open(args.labels, encoding="ascii", errors="replace") as handle:
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) < 5 or parts[0] == "start_micros":
                continue
            try:
                windows.append((int(parts[0]), int(parts[1]), parts[3]))
            except ValueError:
                continue

    stories, labels, families = [], [], []
    for start, end, family in windows:
        story = window_story(times, rows, start, end)
        if story is not None:
            stories.append(story)
            labels.append(1.0)
            families.append(family)

    # Negatives: a window of the same length placed at a random time outside
    # every labelled window. Same construction, no technique.
    spans = [(end - start) for start, end, _ in windows]
    rng = np.random.default_rng(4)
    taken = 0
    attempts = 0
    while taken < args.negatives and attempts < args.negatives * 50:
        attempts += 1
        span = int(rng.choice(spans))
        at = int(rng.integers(times.min() + 1, times.max() - span))
        inside = any(start <= at <= end for start, end, _ in windows)
        if inside:
            continue
        story = window_story(times, rows, at, at + span)
        if story is None:
            continue
        stories.append(story)
        labels.append(0.0)
        families.append("benign")
        taken += 1

    x = np.stack(stories)
    y = np.asarray(labels, dtype=np.float32)
    np.savez_compressed(args.out, x=x, y=y, family=np.array(families))
    print("windows %d malicious, %d benign, shape %s"
          % (int(y.sum()), int((y == 0).sum()), x.shape))


if __name__ == "__main__":
    sys.exit(main())
