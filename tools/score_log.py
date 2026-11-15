#!/usr/bin/env python3
"""Score this machine's own log with an exported model and count its false positives.

The trainer's number is a number about the corpus it was trained on. This is the
other number: what the model does to the stories a real desktop produces -- the
browser, the package manager, the build, the shell that runs the harness. It
reads the behaviour log, builds one story per process exactly as the service
does, scores each with the exported weights, and reports the tail.

The tail is the whole question. A model that flags ten stories in a hundred
thousand is a signal; one that flags three in a hundred is a nuisance. Which one
this is decides whether the model may act or may only advise.

Usage:
    python tools/score_log.py --model target/behaviour-v2.bin \
        --log C:/ProgramData/WenleAV/logs/behaviour.log [--max 20000]
"""

import argparse
import os
import struct
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from train_behaviour import AGGREGATES, HIDDEN, LENGTH, WIDTH, GRU  # noqa: E402


def load_model(path):
    """Read the exporter's format back into a GRU."""
    data = open(path, "rb").read()
    if data[:8] == b"WENLGRU2":
        width, hidden, aggregates = struct.unpack("<III", data[8:20])
        cursor = 20
    elif data[:8] == b"WENLGRU1":
        width, hidden = struct.unpack("<II", data[8:16])
        aggregates = 0
        cursor = 16
    else:
        raise SystemExit("not a model this script can read")
    if width != WIDTH or hidden != HIDDEN:
        raise SystemExit("model width %d/%d does not match %d/%d" % (width, hidden, WIDTH, HIDDEN))

    names = ["w_z", "u_z", "b_z", "w_r", "u_r", "b_r", "w_h", "u_h", "b_h", "w_o", "b_o"]
    if aggregates:
        names.append("w_a")
    model = GRU()
    for name in names:
        count = struct.unpack("<I", data[cursor:cursor + 4])[0]
        cursor += 4
        values = np.frombuffer(data[cursor:cursor + count * 4], dtype="<f4").astype(np.float32)
        cursor += count * 4
        setattr(model, name, values.reshape(getattr(model, name).shape))
    return model


def events(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 3 + WIDTH:
                continue
            try:
                pid = int(fields[0])
                stamp = int(fields[2])
                values = [float(value) for value in fields[3:3 + WIDTH]]
            except ValueError:
                continue
            yield pid, stamp, values


def stories(path, max_stories):
    current = {}
    order = []
    for pid, stamp, values in events(path):
        story = current.setdefault(pid, [])
        story.append(values)
        if len(story) > LENGTH:
            story.pop(0)
        if len(story) % 8 == 0:
            order.append((pid, [row[:] for row in story]))
    # Keep the newest stories and cap the work: the tail is what matters.
    order = order[-max_stories:]
    x = np.zeros((len(order), LENGTH, WIDTH), dtype=np.float32)
    for index, (_pid, story) in enumerate(order):
        x[index, LENGTH - len(story):] = np.asarray(story, dtype=np.float32)
    return x, order


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--max", type=int, default=20000)
    args = parser.parse_args()

    model = load_model(args.model)
    x, order = stories(args.log, args.max)
    print("stories scored: %d" % len(x))
    if len(x) == 0:
        return 1

    probabilities, _ = model.forward(x)
    scores = probabilities[:, 0]
    quantiles = np.quantile(scores, [0.5, 0.9, 0.99, 0.999, 0.9999])
    print("score quantiles: median %.3f p90 %.3f p99 %.3f p99.9 %.3f p99.99 %.3f"
          % tuple(quantiles))
    for threshold in (0.9, 0.99, 0.995, 0.999, 0.9999):
        above = int((scores >= threshold).sum())
        print("  >= %.4f : %6d stories (%.4f %%)" % (
            threshold, above, 100.0 * above / len(scores)))

    top = np.argsort(scores)[-10:][::-1]
    print("highest scores:")
    for index in top:
        pid = order[index][0]
        image = int(round(order[index][1][-1][33] * 8))
        print("  %.4f  pid %-6d image class %d" % (scores[index], pid, image))
    return 0


if __name__ == "__main__":
    sys.exit(main())
