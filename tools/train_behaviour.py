#!/usr/bin/env python3
"""Train the behaviour GRU and export its weights for the service.

The model is deliberately small: one 33-float event vector, a 32-unit GRU, one
output. About ten thousand parameters, which is small enough to embed in the
service and to run in microseconds per event.

What this script is for is the evaluation, not the model. A behaviour model that
scores 95% on the families it was trained on has learned nothing that helps
against the next family, so the default mode is leave-one-family-out: train on
every family but one, test on the one that was never seen, and report the score
per held-out family. That number is the only one worth quoting as "unknown
threat" coverage.

Labels come from `labels.csv`, written by `tools/behaviour-corpus.ps1`: one row
per run with start/end microseconds, a label and a family. A sequence is
labelled by whether any of its events fall inside a window.

Usage:
    python tools/train_behaviour.py --log <behaviour.log> --labels <labels.csv> \
        --out <model.bin> [--holdout <family>] [--epochs 400]
"""

import argparse
import json
import os
import struct
import sys

import numpy as np

WIDTH = 33
LENGTH = 64
HIDDEN = 32
MAX_GAP_US = 5_000_000


def load_events(path):
    """Read the service's log: pid ppid timestamp then WIDTH floats."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) != 3 + WIDTH:
                continue
            try:
                pid = int(parts[0])
                ppid = int(parts[1])
                timestamp = int(parts[2])
                features = [float(value) for value in parts[3:]]
            except ValueError:
                continue
            events.append((pid, ppid, timestamp, features))
    events.sort(key=lambda item: item[2])
    return events


def load_windows(path):
    windows = []
    with open(path, "r", encoding="utf-8") as handle:
        next(handle, None)
        for line in handle:
            parts = line.strip().split(",")
            if len(parts) != 4:
                continue
            try:
                windows.append((int(parts[0]), int(parts[1]), parts[2], parts[3]))
            except ValueError:
                continue
    return windows


def label_for(timestamp, windows):
    for start, end, label, family in windows:
        if start <= timestamp <= end:
            return label, family
    return None, None


def build_sequences(events, windows):
    """Group events by process and contiguous time, then label the group.

    A group is broken when the process changes or more than `MAX_GAP_US`
    passes: a process that was quiet for ten minutes has started a different
    piece of work, and joining the two would teach the model that the gap is
    part of one behaviour.
    """
    sequences = []
    current = []
    current_pid = None
    last_time = None
    for pid, ppid, timestamp, features in events:
        if current and (pid != current_pid or timestamp - last_time > MAX_GAP_US):
            sequences.append((current_pid, current))
            current = []
        current.append((timestamp, features))
        current_pid = pid
        last_time = timestamp
    if current:
        sequences.append((current_pid, current))

    labelled = []
    for pid, items in sequences:
        hits = []
        for timestamp, _ in items:
            label, family = label_for(timestamp, windows)
            if label is not None:
                hits.append((label, family))
        if not hits:
            # No window mentions this sequence: it is background work from the
            # machine itself, which is benign by default. Keeping it is what
            # teaches the model what ordinary work looks like.
            labelled.append(("benign", "background", [features for _, features in items]))
            continue
        labels = [label for label, _ in hits]
        label = "malicious" if "malicious" in labels else "benign"
        family = hits[0][1]
        labelled.append((label, family, [features for _, features in items]))
    return labelled


def pad(sequence):
    """The last LENGTH events, left-padded with zeros."""
    if len(sequence) > LENGTH:
        sequence = sequence[-LENGTH:]
    missing = LENGTH - len(sequence)
    return np.array([[0.0] * WIDTH] * missing + sequence, dtype=np.float32)


class GRU:
    """A one-layer GRU and the arithmetic to train it.

    Written out rather than imported: the same equations have to be reimplemented
    in Rust for inference, and a trainer whose definition of a GRU lives in a
    library is a trainer whose model the service would have to infer from the
    exported weights and a hope.
    """

    def __init__(self, seed=7):
        rng = np.random.default_rng(seed)
        scale = 1.0 / np.sqrt(HIDDEN)

        def block(rows, cols):
            return rng.uniform(-scale, scale, size=(rows, cols)).astype(np.float32)

        self.w_z = block(HIDDEN, WIDTH)
        self.u_z = block(HIDDEN, HIDDEN)
        self.b_z = np.zeros(HIDDEN, dtype=np.float32)
        self.w_r = block(HIDDEN, WIDTH)
        self.u_r = block(HIDDEN, HIDDEN)
        self.b_r = np.zeros(HIDDEN, dtype=np.float32)
        self.w_h = block(HIDDEN, WIDTH)
        self.u_h = block(HIDDEN, HIDDEN)
        self.b_h = np.zeros(HIDDEN, dtype=np.float32)
        self.w_o = rng.uniform(-scale, scale, size=(1, HIDDEN)).astype(np.float32)
        self.b_o = np.zeros(1, dtype=np.float32)

    def params(self):
        return [
            self.w_z, self.u_z, self.b_z,
            self.w_r, self.u_r, self.b_r,
            self.w_h, self.u_h, self.b_h,
            self.w_o, self.b_o,
        ]

    def forward(self, batch):
        """Return the output probabilities and the cache for the backward pass."""
        batch_size = batch.shape[0]
        h = np.zeros((batch_size, HIDDEN), dtype=np.float32)
        cache = []
        for step in range(LENGTH):
            x = batch[:, step, :]
            z = sigmoid(x @ self.w_z.T + h @ self.u_z.T + self.b_z)
            r = sigmoid(x @ self.w_r.T + h @ self.u_r.T + self.b_r)
            candidate = np.tanh(x @ self.w_h.T + (r * h) @ self.u_h.T + self.b_h)
            previous = h
            h = (1.0 - z) * h + z * candidate
            cache.append((x, previous, z, r, candidate))
        logits = h @ self.w_o.T + self.b_o
        probability = sigmoid(logits)
        return probability, (cache, h)

    def backward(self, batch, probability, labels, cache, sample_weight):
        cache_steps, final_h = cache
        batch_size = batch.shape[0]
        grads = [np.zeros_like(parameter) for parameter in self.params()]

        # Output layer.
        delta_out = ((probability - labels) * sample_weight).astype(np.float32)  # (batch, 1)
        grads[9] += delta_out.T @ final_h
        grads[10] += delta_out.sum(axis=0)

        delta_h = delta_out @ self.w_o
        for step in reversed(range(LENGTH)):
            x, previous, z, r, candidate = cache_steps[step]
            delta_candidate = delta_h * z
            delta_z = delta_h * (candidate - previous)
            delta_h_prev = delta_h * (1.0 - z)

            # tanh' and sigmoid' at their own pre-activations.
            d_candidate = delta_candidate * (1.0 - candidate ** 2)
            d_z = delta_z * z * (1.0 - z)
            d_r = (d_candidate @ self.u_h) * previous * r * (1.0 - r)

            grads[6] += d_candidate.T @ x
            grads[7] += d_candidate.T @ (r * previous)
            grads[8] += d_candidate.sum(axis=0)

            grads[0] += d_z.T @ x
            grads[1] += d_z.T @ previous
            grads[2] += d_z.sum(axis=0)

            grads[3] += d_r.T @ x
            grads[4] += d_r.T @ previous
            grads[5] += d_r.sum(axis=0)

            delta_h_prev += d_candidate @ self.u_h * r
            delta_h_prev += d_z @ self.u_z
            delta_h_prev += d_r @ self.u_r
            delta_h = delta_h_prev
        return grads


def sigmoid(value):
    return 1.0 / (1.0 + np.exp(-np.clip(value, -30.0, 30.0)))


def train(model, sequences, labels, epochs, class_weight):
    positives = [index for index, label in enumerate(labels) if label > 0.5]
    background = [index for index, label in enumerate(labels) if label <= 0.5]
    order = np.array(background + positives * 12)
    rng = np.random.default_rng(11)
    weights = [np.zeros_like(parameter) for parameter in model.params()]
    moments = [np.zeros_like(parameter) for parameter in model.params()]
    learning_rate = 0.01
    for epoch in range(epochs):
        rng.shuffle(order)
        total = 0.0
        for start in range(0, len(order), 16):
            batch_index = order[start:start + 16]
            batch = np.stack([sequences[index] for index in batch_index])
            target = np.array([[labels[index]] for index in batch_index], dtype=np.float32)
            probability, cache = model.forward(batch)
            # Malicious sequences are rarer than benign ones, so each of them
            # counts for more: an unweighted mean would learn "say benign".
            sample_weight = np.where(target > 0.5, class_weight, 1.0).astype(np.float32)
            loss = -(target * np.log(probability + 1e-7) + (1 - target) * np.log(1 - probability + 1e-7))
            total += float((loss * sample_weight).mean())
            grads = model.backward(batch, probability, target, cache, sample_weight)
            for index, gradient in enumerate(grads):
                weights[index] = 0.9 * weights[index] + 0.1 * gradient
                moments[index] = 0.999 * moments[index] + 0.001 * gradient ** 2
                parameters = model.params()
                updated = parameters[index] - learning_rate * (weights[index] / (1 - 0.9 ** (epoch + 1))) / (
                    np.sqrt(moments[index] / (1 - 0.999 ** (epoch + 1))) + 1e-8
                )
                setattr_parameter(model, index, updated.astype(np.float32))
        if epoch % 50 == 0:
            print("epoch %3d  loss %.4f" % (epoch, total / max(1, len(order) // 16)), flush=True)


PARAMETER_NAMES = [
    "w_z", "u_z", "b_z", "w_r", "u_r", "b_r", "w_h", "u_h", "b_h", "w_o", "b_o",
]


def setattr_parameter(model, index, value):
    setattr(model, PARAMETER_NAMES[index], value)


def export(model, path):
    with open(path, "wb") as handle:
        handle.write(b"WENLGRU1")
        handle.write(struct.pack("<II", WIDTH, HIDDEN))
        for name in PARAMETER_NAMES:
            value = getattr(model, name).astype("<f4")
            handle.write(struct.pack("<I", value.size))
            handle.write(value.tobytes())
    print("weights written to %s (%d bytes)" % (path, os.path.getsize(path)))


def evaluate(model, sequences, labels):
    if not sequences:
        return 0.0, 0.0
    batch = np.stack(sequences)
    probability, _ = model.forward(batch)
    scores = probability.reshape(-1)
    truth = np.array(labels)
    malicious = scores[truth == 1]
    benign = scores[truth == 0]
    recall = float((malicious > 0.5).mean()) if malicious.size else 0.0
    false_positive = float((benign > 0.5).mean()) if benign.size else 0.0
    return recall, false_positive


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--holdout", default=None, help="family to leave out")
    parser.add_argument("--epochs", type=int, default=400)
    parser.add_argument("--min-sequences", type=int, default=8)
    args = parser.parse_args()

    events = load_events(args.log)
    windows = load_windows(args.labels)
    print("events %d, windows %d" % (len(events), len(windows)))
    sequences = build_sequences(events, windows)
    print("sequences %d" % len(sequences))

    def is_malicious(label):
        return 1.0 if label == "malicious" else 0.0

    report = {}
    if args.holdout:
        train_items = [item for item in sequences if item[1] != args.holdout]
        test_items = [item for item in sequences if item[1] == args.holdout]
        if len(train_items) < args.min_sequences:
            print("not enough sequences to train (%d)" % len(train_items))
            return 1
        model = GRU()
        train(
            model,
            [pad(item[2]) for item in train_items],
            [is_malicious(item[0]) for item in train_items],
            args.epochs,
            class_weight=8.0,
        )
        recall, false_positive = evaluate(
            model, [pad(item[2]) for item in test_items], [is_malicious(item[0]) for item in test_items]
        )
        report[args.holdout] = {"recall": recall, "false_positive": false_positive, "sequences": len(test_items)}
        print(json.dumps(report, indent=2))
        return 0

    model = GRU()
    train(
        model,
        [pad(item[2]) for item in sequences],
        [is_malicious(item[0]) for item in sequences],
        args.epochs,
        class_weight=8.0,
    )
    recall, false_positive = evaluate(
        model, [pad(item[2]) for item in sequences], [is_malicious(item[0]) for item in sequences]
    )
    print("training-set recall %.3f  false positive %.3f" % (recall, false_positive))
    export(model, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
