#!/usr/bin/env python3
"""The hybrid in PyTorch: Conv1d over events, then a GRU, then the aggregates.

The hand-written version in `train_hybrid.py` underfits (loss stuck near 0.24)
because a recurrent backward pass written by hand is easy to get subtly wrong;
PyTorch is the honest way to find out whether the architecture is better before
porting anything to Rust.

Usage:
    python tools/train_hybrid_torch.py --corpus target/corpus-50.npz \
        --out target/hybrid_torch.pt [--epochs 30]
"""

import argparse
import sys

import numpy as np
import torch
from torch import nn

sys.path.insert(0, __file__.rsplit("\\", 1)[0])

from train_behaviour import AGGREGATES, LENGTH, WIDTH  # noqa: E402


def aggregates(x):
    """The twelve story aggregates, matching av_behaviour::sequence."""
    mask = (x.abs().sum(dim=2) > 0).float()
    total = mask.sum(dim=1, keepdim=True).clamp(min=1.0)
    columns = [3, 1, 8, 9, 10, 2, 11, 18, 19, 20, 32]
    fractions = [(x[:, :, index] * mask).sum(dim=1, keepdim=True) / total for index in columns]
    length = (total / LENGTH).clamp(max=1.0)
    return torch.cat(fractions + [length], dim=1)


class Hybrid(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv = nn.Conv1d(WIDTH, 16, kernel_size=3, padding=2)
        self.gru = nn.GRU(16, 32, batch_first=True)
        self.head = nn.Linear(32 + AGGREGATES, 1)

    def forward(self, x):
        # (B, L, W) -> (B, W, L) for the convolution, then back for the GRU.
        features = torch.relu(self.conv(x.transpose(1, 2))).transpose(1, 2)
        output, _ = self.gru(features)
        last = output[:, -1, :]
        return self.head(torch.cat([last, aggregates(x)], dim=1)).squeeze(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()

    data = np.load(args.corpus, allow_pickle=False)
    x = torch.tensor(data["x"], dtype=torch.float32)
    y = torch.tensor(data["y"], dtype=torch.float32)
    index = np.random.default_rng(11).permutation(len(x))
    cut = int(len(x) * 0.8)
    train_index = torch.tensor(index[:cut])
    test_index = torch.tensor(index[cut:])

    model = Hybrid()
    optimizer = torch.optim.Adam(model.parameters(), lr=2e-3)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(4.0))
    for epoch in range(args.epochs):
        model.train()
        permutation = torch.randperm(len(train_index))
        total = 0.0
        for start in range(0, len(permutation), 64):
            batch = train_index[permutation[start:start + 64]]
            optimizer.zero_grad()
            logits = model(x[batch])
            loss = loss_fn(logits, y[batch])
            loss.backward()
            # The same clipping the numpy trainer uses: a saturated sigmoid on a
            # small corpus is what turned every score into 1.000 before.
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total += float(loss) * len(batch)
        print("epoch %3d  loss %.4f" % (epoch, total / len(train_index)))

    model.eval()
    with torch.no_grad():
        scores = torch.sigmoid(model(x[test_index])).numpy()
    labels = y[test_index].numpy()
    benign = scores[labels == 0]
    malicious = scores[labels == 1]
    threshold = float(np.quantile(benign, 0.999))
    print("held-out benign max %.3f p99.9 %.3f" % (benign.max(), threshold))
    for t in (0.9, 0.95, 0.98, 0.99):
        print("threshold %.2f: benign %d/%d, malicious %.1f%%"
              % (t, int((benign >= t).sum()), len(benign), 100.0 * (malicious >= t).mean()))
    torch.save(model.state_dict(), args.out)
    print("weights written to %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
