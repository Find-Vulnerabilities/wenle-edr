#!/usr/bin/env python3
"""Score one file with the script model.

The model is trained once and saved; scoring a file then loads it and answers in
seconds. Training only happens when no model is available or --save asks for a
new one, which is how the product works too: the other two models (the PE trees
and the behaviour story model) are embedded binaries that are loaded, never
trained, at runtime.

Usage:
  python tools/score_file.py --scripts C:\\...\\script-ai --file sample.bat
  python tools/score_file.py --scripts C:\\...\\script-ai --file sample.bat --save target/script-model.txt
"""
import argparse
import os
import sys

import lightgbm as lgb
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from script_train import read_benign_from_disk, read_directory, read_parquet_malicious, vectorize

DEFAULT_MODEL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "target", "script-model.txt")


def report(model, path):
    with open(path, "rb") as handle:
        data = handle.read()
    extension = os.path.splitext(path)[1].lower()
    probability = float(model.predict(vectorize([(data, extension, 0)]))[0])
    safe = path.encode("ascii", "replace").decode("ascii")
    print("file: %s (%d bytes)" % (safe, len(data)), flush=True)
    print("score: %.4f" % probability, flush=True)
    for threshold, meaning in ((0.7979, "1% real-script FP"), (0.5, "half"),
                               (0.1, "strict"), (1.0, "perfect")):
        print("   threshold %.4f (%s): %s" % (
            threshold, meaning, "MALICIOUS" if probability > threshold else "below"), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scripts", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--model", default=None)
    parser.add_argument("--save", default=None)
    parser.add_argument("--malicious-limit", type=int, default=3000)
    parser.add_argument("--benign-per-extension", type=int, default=600)
    args = parser.parse_args()

    model_path = args.model
    if model_path is None and os.path.exists(DEFAULT_MODEL):
        model_path = DEFAULT_MODEL
    if model_path is not None:
        print("model: %s (loaded, no training)" % model_path, flush=True)
        report(lgb.Booster(model_file=model_path), args.file)
        return

    rows = []
    rows += [(d, e, 1) for d, e, l in read_parquet_malicious(args.scripts, args.malicious_limit)]
    rows += read_directory(os.path.join(args.scripts, "synthetic", "malicious"), 1)
    rows += read_directory(os.path.join(args.scripts, "synthetic", "benign"), 0)
    rows += read_benign_from_disk({e: args.benign_per_extension
                                   for e in (".ps1", ".psm1", ".js", ".vbs", ".bat", ".py", ".cmd")})
    print("training rows:", len(rows), flush=True)
    labels = np.asarray([label for _, _, label in rows], dtype=np.int32)
    matrix = vectorize(rows)
    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=800, learning_rate=0.05,
        num_leaves=127, min_child_samples=10, feature_fraction=0.3,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    model.fit(matrix, labels)
    save_path = args.save or DEFAULT_MODEL
    model.booster_.save_model(save_path)
    print("model saved to %s" % save_path, flush=True)
    report(model.booster_, args.file)


if __name__ == "__main__":
    main()
