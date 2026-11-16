#!/usr/bin/env python3
"""A convolutional front-end before the GRU, and the same evaluation.

The GRU reads events one at a time and has to learn that `certutil` followed by
`-urlcache` is one act; a one-dimensional convolution over three adjacent events
learns that directly, and the recurrent layer then reads the filtered story. The
hybrid is the arrangement that security vendors report as best on this kind of
telemetry, and this compares it with the pure GRU on the same corpus.

The interface is the trainer's: `forward(batch)` returns a probability and a
cache, `backward(batch, probability, target, cache, weights)` returns gradients.

Usage:
    python tools/train_hybrid.py --corpus target/corpus-50.npz \
        --out target/hybrid.npz [--epochs 30]
"""

import argparse
import sys

import numpy as np

sys.path.insert(0, __file__.rsplit("\\", 1)[0])

from train_behaviour import (  # noqa: E402
    AGGREGATES,
    HIDDEN,
    LENGTH,
    WIDTH,
    batch_aggregates,
    metrics,
    scores_of,
    sigmoid,
    threshold_at,
)

CHANNELS = 16
KERNEL = 3
LEARNING_RATE = 0.01
WEIGHT_DECAY = 0.0005


class ConvGru:
    def __init__(self, seed=1):
        rng = np.random.default_rng(seed)
        scale = np.sqrt(2.0 / (KERNEL * WIDTH))
        self.w_c = rng.normal(0.0, scale, (CHANNELS, KERNEL * WIDTH)).astype(np.float32)
        self.b_c = np.zeros(CHANNELS, dtype=np.float32)
        self.w_z = rng.uniform(-0.1, 0.1, (HIDDEN, CHANNELS)).astype(np.float32)
        self.u_z = rng.uniform(-0.1, 0.1, (HIDDEN, HIDDEN)).astype(np.float32)
        self.b_z = np.zeros(HIDDEN, dtype=np.float32)
        self.w_r = rng.uniform(-0.1, 0.1, (HIDDEN, CHANNELS)).astype(np.float32)
        self.u_r = rng.uniform(-0.1, 0.1, (HIDDEN, HIDDEN)).astype(np.float32)
        self.b_r = np.zeros(HIDDEN, dtype=np.float32)
        self.w_h = rng.uniform(-0.1, 0.1, (HIDDEN, CHANNELS)).astype(np.float32)
        self.u_h = rng.uniform(-0.1, 0.1, (HIDDEN, HIDDEN)).astype(np.float32)
        self.b_h = np.zeros(HIDDEN, dtype=np.float32)
        self.w_o = rng.uniform(-0.1, 0.1, (1, HIDDEN)).astype(np.float32)
        self.b_o = np.zeros(1, dtype=np.float32)
        self.w_a = np.zeros((1, AGGREGATES), dtype=np.float32)

    def names(self):
        return [
            "w_c", "b_c", "w_z", "u_z", "b_z", "w_r", "u_r", "b_r",
            "w_h", "u_h", "b_h", "w_o", "b_o", "w_a",
        ]

    def params(self):
        return [getattr(self, name) for name in self.names()]

    def set_param(self, index, value):
        setattr(self, self.names()[index], value.astype(np.float32))

    def conv(self, batch):
        # (B, L, W) -> (B, L, C). The window at t is events t..t+K-1 with zeros
        # past the end, so the last event still sees a padded window.
        padded = np.concatenate([batch, np.zeros((len(batch), KERNEL - 1, WIDTH), np.float32)], axis=1)
        windows = np.concatenate([padded[:, k:k + LENGTH, :] for k in range(KERNEL)], axis=2)
        pre = windows @ self.w_c.T + self.b_c
        return np.maximum(pre, 0.0), pre, windows

    def forward(self, batch):
        features, pre, windows = self.conv(batch)
        steps = []
        h = np.zeros((len(batch), HIDDEN), np.float32)
        for t in range(LENGTH):
            x = features[:, t, :]
            z = sigmoid(x @ self.w_z.T + h @ self.u_z.T + self.b_z)
            r = sigmoid(x @ self.w_r.T + h @ self.u_r.T + self.b_r)
            candidate = np.tanh(x @ self.w_h.T + (r * h) @ self.u_h.T + self.b_h)
            h = (1 - z) * h + z * candidate
            steps.append((x, z, r, candidate, h, h.copy()))
        aggregates = batch_aggregates(batch)
        logits = h @ self.w_o.T + self.b_o + aggregates @ self.w_a.T
        probability = sigmoid(logits)
        return probability, (steps, features, pre, windows, aggregates, h)

    def backward(self, batch, probability, target, cache, sample_weight):
        steps, features, pre, windows, aggregates, final_h = cache
        delta_out = (probability - target) * sample_weight[:, None]
        grads = [np.zeros_like(p) for p in self.params()]
        names = self.names()
        index = {name: i for i, name in enumerate(names)}
        grads[index["w_o"]] += delta_out.T @ final_h
        grads[index["b_o"]] += delta_out.sum(axis=0)
        grads[index["w_a"]] += delta_out.T @ aggregates

        dconv = np.zeros_like(features)
        dh = delta_out @ self.w_o
        for t in reversed(range(LENGTH)):
            x, z, r, candidate, h, _h_snapshot = steps[t]
            previous = steps[t - 1][4] if t > 0 else np.zeros_like(h)
            dh = dh + 0.0
            dcandidate = dh * z * (1 - candidate ** 2)
            dz = dh * (candidate - previous)
            dr = (dcandidate @ self.u_h) * previous
            # The candidate path: d(candidate)/d(r*h) = u_h, so the gradient
            # towards h is (dc @ u_h) * r, not (dc * r) @ u_h -- multiplying
            # before the matmul mixes the batch and hidden axes.
            dprev = dh * (1 - z) + (dcandidate @ self.u_h) * r
            dz_pre = dz * z * (1 - z)
            dr_pre = dr * r * (1 - r)
            grads[index["w_z"]] += dz_pre.T @ x
            grads[index["u_z"]] += dz_pre.T @ previous
            grads[index["b_z"]] += dz_pre.sum(axis=0)
            grads[index["w_r"]] += dr_pre.T @ x
            grads[index["u_r"]] += dr_pre.T @ previous
            grads[index["b_r"]] += dr_pre.sum(axis=0)
            grads[index["w_h"]] += dcandidate.T @ x
            grads[index["u_h"]] += dcandidate.T @ (r * previous)
            grads[index["b_h"]] += dcandidate.sum(axis=0)
            dconv[:, t, :] += dz_pre @ self.w_z + dr_pre @ self.w_r + dcandidate @ self.w_h
            dh = dprev

        relu_mask = (pre > 0).astype(np.float32)
        dpre = dconv * relu_mask
        flat = dpre.reshape(-1, CHANNELS).T
        grads[index["w_c"]] += flat @ windows.reshape(-1, KERNEL * WIDTH)
        grads[index["b_c"]] += dpre.sum(axis=(0, 1))
        return grads


def train(model, x, y, epochs):
    weights = [np.zeros_like(p) for p in model.params()]
    moments = [np.zeros_like(p) for p in model.params()]
    for epoch in range(epochs):
        order = np.random.default_rng(epoch).permutation(len(x))
        total = 0.0
        for start in range(0, len(order), 64):
            batch_index = order[start:start + 64]
            batch = x[batch_index]
            target = y[batch_index][:, None]
            probability, cache = model.forward(batch)
            clipped = np.clip(probability, 1e-6, 1 - 1e-6)
            total += float(-(target * np.log(clipped) + (1 - target) * np.log(1 - clipped)).mean())
            weight = np.where(target == 1, 4.0, 1.0).astype(np.float32)
            grads = model.backward(batch, probability, target, cache, weight[:, 0])
            for i, gradient in enumerate(grads):
                gradient = np.clip(gradient, -1.0, 1.0)
                weights[i] = 0.9 * weights[i] + 0.1 * gradient
                moments[i] = 0.999 * moments[i] + 0.001 * gradient ** 2
                updated = model.params()[i] - LEARNING_RATE * (weights[i] / (1 - 0.9 ** (epoch + 1))) / (
                    np.sqrt(moments[i] / (1 - 0.999 ** (epoch + 1))) + 1e-8
                )
                updated -= WEIGHT_DECAY * model.params()[i]
                model.set_param(i, updated)
        print("epoch %3d  loss %.4f" % (epoch, total / max(1, len(order) // 64)))


def save(model, path):
    np.savez_compressed(
        path,
        **{name: getattr(model, name) for name in model.names()},
        format=np.array(["conv-gru-v1"]),
        channels=np.array([CHANNELS]),
        kernel=np.array([KERNEL]),
    )
    print("weights written to %s" % path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()

    data = np.load(args.corpus, allow_pickle=False)
    x, y = data["x"], data["y"]
    index = np.random.default_rng(11).permutation(len(x))
    cut = int(len(x) * 0.8)
    train_index, test_index = index[:cut], index[cut:]
    model = ConvGru()
    train(model, x[train_index], y[train_index], args.epochs)

    benign = scores_of(model, list(x[test_index][y[test_index] == 0]))
    malicious = scores_of(model, list(x[test_index][y[test_index] == 1]))
    threshold = threshold_at(benign, np.zeros(len(benign), np.float32), 0.001)
    print("held-out benign max %.3f p99.9 %.3f, threshold %.3f"
          % (benign.max(), np.quantile(benign, 0.999), threshold))
    print("held-out malicious above threshold: %.1f%%" % (100.0 * (malicious >= threshold).mean()))
    save(model, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
