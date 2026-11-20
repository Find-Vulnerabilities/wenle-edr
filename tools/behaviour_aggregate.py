#!/usr/bin/env python3
"""A stable second opinion on the behaviour sequences: aggregate + LightGBM.

The GRU's score is unstable across seeds on this corpus and its top of the
benign distribution overlaps the attacks. The same sequences carry simpler
evidence: what operations a story contains, how many, and how concentrated they
are. Those aggregates are what a tree ensemble can separate reliably, and they
are cheap to compute in Rust.

This is a measurement, not a decision: it says whether the information in the
sequence is being left on the table by the recurrent model.

Usage: python tools/behaviour_aggregate.py --npz behaviour-merged2.npz
"""
import argparse

import lightgbm as lgb
import numpy as np


def aggregate(x):
    """Per-sequence statistics over the 47 features of its 64 events.

    Mean, peak, total, spread and presence say what the story did; the sliding
    window peak says how tightly it did it, which is what separates a burst from
    a background process that happens to contain one suspicious call.
    """
    mean = x.mean(axis=1)
    peak = x.max(axis=1)
    total = x.sum(axis=1)
    spread = x.std(axis=1)
    presence = (x > 0.0).sum(axis=1) / x.shape[1]
    counts = (x > 0.5).sum(axis=1)
    window = 8
    steps = x.shape[1] - window + 1
    if steps > 0:
        rolled = np.stack([x[:, start:start + window].sum(axis=1) for start in range(steps)], axis=0)
        burst = rolled.max(axis=0)
    else:
        burst = total
    return np.concatenate([mean, peak, total, spread, presence, counts, burst], axis=1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--npz", required=True)
    parser.add_argument("--trees", type=int, default=400)
    parser.add_argument("--fprs", default="0.01,0.001,0.0001")
    parser.add_argument("--augment", action="store_true")
    parser.add_argument("--save", default=None)
    parser.add_argument("--leaves", type=int, default=63)
    parser.add_argument("--pos-weight", type=float, default=1.0)
    parser.add_argument("--mode", default="aggregate", choices=("aggregate", "flat", "both", "ensemble"))
    args = parser.parse_args()

    data = np.load(args.npz, allow_pickle=True)
    raw = data["x"].astype(np.float32)
    if args.mode == "flat":
        x = raw.reshape(len(raw), -1)
    elif args.mode == "both":
        x = np.concatenate([aggregate(raw), raw.reshape(len(raw), -1)], axis=1)
    else:
        x = aggregate(raw)
    y = data["y"].astype(np.int32)
    families = data["family"]
    print("sequences %d, features %d, malicious %d" % (len(x), x.shape[1], int(y.sum())))

    order = np.random.default_rng(11).permutation(len(x))
    cut = int(len(x) * 0.7)
    train, test = order[:cut], order[cut:]
    if args.mode == "ensemble":
        aggregate_part = aggregate(raw)
        flat_part = raw.reshape(len(raw), -1)
        both_part = np.concatenate([aggregate_part, flat_part], axis=1)
        models = []
        for part in (aggregate_part, flat_part, both_part):
            fitted = lgb.LGBMClassifier(
                objective="binary", n_estimators=args.trees, learning_rate=0.05,
                num_leaves=args.leaves, min_child_samples=20, feature_fraction=0.5,
        scale_pos_weight=args.pos_weight,
                bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
            )
            fitted.fit(part[train], y[train])
            models.append(fitted)
        probability = np.mean([fitted.predict_proba(part[test])[:, 1]
                               for fitted, part in zip(models, (aggregate_part, flat_part, both_part))], axis=0)
        truth = y[test]
        benign = probability[truth == 0]
        malicious = probability[truth == 1]
        family_scores = {}
        for score, family in zip(probability, families[test]):
            family_scores[str(family)] = max(family_scores.get(str(family), 0.0), float(score))
        for value in (0.01, 0.001, 0.0001):
            threshold = float(np.quantile(benign, 1.0 - value)) if len(benign) else 0.5
            caught = sum(1 for score in family_scores.values() if score > threshold)
            print("ENSEMBLE FPR %.4f -> sequence recall %.1f%%, family recall %.1f%% (%d/%d), threshold %.4f"
                  % (value, 100 * (malicious > threshold).mean(), 100.0 * caught / max(len(family_scores), 1),
                     caught, len(family_scores), threshold))
        return

    model = lgb.LGBMClassifier(
        objective="binary", n_estimators=args.trees, learning_rate=0.05,
        num_leaves=args.leaves, min_child_samples=20, feature_fraction=0.5,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )
    if args.augment and x.ndim == 3:
        shifted = x[train].copy()
        shifted[:, :8, :] = 0.0
        x_train = np.concatenate([x[train], shifted], axis=0)
        y_train = np.concatenate([y[train], y[train]], axis=0)
        model.fit(x_train, y_train)
    else:
        model.fit(x[train], y[train])
    if args.save:
        model.booster_.save_model(args.save)
        print("saved", args.save)
    probability = model.predict_proba(x[test])[:, 1]
    truth = y[test]
    benign = probability[truth == 0]
    malicious = probability[truth == 1]

    held_families = sorted({str(f) for f, label in zip(families[test], truth) if label == 1})
    family_scores = {}
    for score, family in zip(probability, families[test]):
        family_scores[str(family)] = max(family_scores.get(str(family), 0.0), float(score))
    for value in (0.01, 0.001, 0.0001):
        threshold = float(np.quantile(benign, 1.0 - value)) if len(benign) else 0.5
        caught = sum(1 for score in family_scores.values() if score > threshold)
        print("FPR %.4f -> sequence recall %.1f%%, family recall %.1f%% (%d/%d), threshold %.4f"
              % (value, 100 * (malicious > threshold).mean(), 100.0 * caught / max(len(family_scores), 1),
                 caught, len(family_scores), threshold))


if __name__ == "__main__":
    main()
