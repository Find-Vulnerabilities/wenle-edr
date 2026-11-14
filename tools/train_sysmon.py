#!/usr/bin/env python3
"""Train on public Sysmon attacks and test on this machine's corpus.

Two questions, and this script answers both:

1. Does a model trained on OTRF's public attack captures separate malicious
   Sysmon behaviour from ordinary work?
2. Does it transfer to the families this machine generated -- behaviours it never
   saw, expressed in the telemetry our driver actually reports?

The transfer number is the one that matters. A model that scores well on the
captures it was trained on has learned those captures.

Usage:
    python tools/train_sysmon.py --datasets target/datasets --corpus target/corpus.npz \
        --out target/sysmon-model.bin [--epochs 120]
"""

import argparse
import io
import json
import os
import sys
import tarfile
import tempfile
import zipfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sysmon_to_features import LENGTH, WIDTH, convert  # noqa: E402
from train_behaviour import GRU, metrics, scores_of, threshold_at, train  # noqa: E402


def extract(archive, target):
    name = archive.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            handle.extractall(target)
        return
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(archive, "r:gz") as handle:
            handle.extractall(target)


def load_dataset(path, work):
    sequences = []
    if path.lower().endswith((".zip", ".tar.gz", ".tgz")):
        folder = tempfile.mkdtemp(dir=work)
        try:
            extract(path, folder)
            for root, _dirs, files in os.walk(folder):
                for name in files:
                    if name.lower().endswith(".json"):
                        sequences.extend(convert(os.path.join(root, name)))
        except (zipfile.BadZipFile, tarfile.TarError, OSError):
            return []
    elif path.lower().endswith(".json"):
        sequences.extend(convert(path))
    return sequences


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets", required=True)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--epochs", type=int, default=120)
    parser.add_argument("--fpr", type=float, default=0.001)
    args = parser.parse_args()

    attack_sequences = []
    with tempfile.TemporaryDirectory() as work:
        for name in sorted(os.listdir(args.datasets)):
            path = os.path.join(args.datasets, name)
            if not os.path.isfile(path):
                continue
            found = load_dataset(path, work)
            print("%-70s %3d sequences" % (name, len(found)))
            attack_sequences.extend(found)

    stored = np.load(args.corpus, allow_pickle=False)
    x = stored["x"]
    y = stored["y"]
    families = stored["family"]
    benign = x[y == 0]
    print("attack sequences %d, host benign %d" % (len(attack_sequences), len(benign)))
    if not attack_sequences or len(benign) == 0:
        return 1

    train_x = np.array(attack_sequences, dtype=np.float32)
    train_y = np.ones(len(train_x), dtype=np.float32)
    mixed_x = np.concatenate([train_x, benign])
    mixed_y = np.concatenate([train_y, np.zeros(len(benign), dtype=np.float32)])

    model = GRU()
    train(model, list(mixed_x), list(mixed_y), args.epochs, class_weight=4.0)

    scores = scores_of(model, list(mixed_x))
    threshold = threshold_at(scores, list(mixed_y), args.fpr)
    result = metrics(scores, list(mixed_y), threshold)
    print("train: recall %.3f fp %.4f auc %.3f threshold %.3f" % (
        result["recall"], result["false_positive"], result["auc"], threshold))

    # Transfer: every host family the model never saw.
    transfer_x = x[y == 1]
    transfer_families = families[y == 1]
    transfer_scores = scores_of(model, list(transfer_x))
    print("transfer by family (threshold %.3f):" % threshold)
    rows = []
    for family in sorted(set(transfer_families.tolist())):
        mask = transfer_families == family
        recall = float((transfer_scores[mask] > threshold).mean())
        rows.append((family, recall, int(mask.sum())))
    for family, recall, count in rows:
        print("  %-22s recall %.2f  (n=%d)" % (family, recall, count))
    overall = float((transfer_scores > threshold).mean())
    print("transfer overall recall %.3f" % overall)
    return 0 if overall > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
