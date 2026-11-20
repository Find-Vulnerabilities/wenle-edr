#!/usr/bin/env python3
"""Hard-negative mining for the story model.

The model saturates near 1 on ordinary work: registry tracing and prefetch
writes score 0.999. One cause is that the benign class it trains on is a random
sample, and the sequences that look like attacks are rare enough to be left out.

This mines them: train a first model, score the benign sequences it was not
trained on, take the ones it scores highest as extra negatives, retrain, and
measure on benign sequences the second model has never seen -- so the threshold
is still calibrated on unseen work.

Usage: python tools/behaviour_mine.py --mal NPZ --benign NPZ
"""
import argparse

import lightgbm as lgb
import numpy as np


def flat(x):
    return x.reshape(len(x), -1)


def make_model(trees=500):
    return lgb.LGBMClassifier(
        objective="binary", n_estimators=trees, learning_rate=0.05,
        num_leaves=255, min_child_samples=20, feature_fraction=0.5,
        bagging_fraction=0.8, bagging_freq=1, n_jobs=6, random_state=11, verbose=-1,
    )


def evaluate(probability, labels, families):
    truth = np.array(labels)
    benign = probability[truth == 0]
    malicious = probability[truth == 1]
    family_scores = {}
    for score, label, family in zip(probability, truth, families):
        if label == 1:
            family_scores[str(family)] = max(family_scores.get(str(family), 0.0), float(score))
    for value in (0.01, 0.001, 0.0001):
        threshold = float(np.quantile(benign, 1.0 - value)) if len(benign) else 0.5
        caught = sum(1 for score in family_scores.values() if score > threshold)
        print("FPR %.4f -> family recall %.1f%% (%d/%d), threshold %.5f"
              % (value, 100.0 * caught / max(len(family_scores), 1), caught, len(family_scores), threshold))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mal", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--benign-train", type=int, default=15000)
    parser.add_argument("--hard", type=int, default=4000)
    args = parser.parse_args()

    mal = np.load(args.mal, allow_pickle=True)
    ben = np.load(args.benign, allow_pickle=True)
    keep = mal["y"] == 1
    x_mal, y_mal = flat(mal["x"][keep]), mal["y"][keep]
    fam_mal = mal["family"][keep]
    x_ben, y_ben = flat(ben["x"]), ben["y"]
    fam_ben = ben["family"]

    rng = np.random.default_rng(11)
    order = rng.permutation(len(x_ben))
    train_index = order[: args.benign_train]
    pool_index = order[args.benign_train:]

    first = make_model()
    first.fit(np.concatenate([x_mal, x_ben[train_index]]),
              np.concatenate([y_mal, y_ben[train_index]]))
    pool_scores = first.predict_proba(x_ben[pool_index])[:, 1]
    hard_index = pool_index[np.argsort(pool_scores)[-args.hard:]]

    print("first model: benign train %d, pool %d, hard %d"
          % (len(train_index), len(pool_index), len(hard_index)), flush=True)

    # The evaluation benign set excludes both the training benign and the hard
    # negatives, so the threshold is calibrated on work the model has not seen.
    used = np.concatenate([train_index, hard_index])
    test_mask = np.ones(len(x_ben), dtype=bool)
    test_mask[used] = False
    x_eval = np.concatenate([x_mal, x_ben[test_mask]])
    y_eval = np.concatenate([y_mal, y_ben[test_mask]])
    fam_eval = np.concatenate([fam_mal, fam_ben[test_mask]])

    second = make_model()
    second.fit(np.concatenate([x_mal, x_ben[train_index], x_ben[hard_index]]),
               np.concatenate([y_mal, y_ben[train_index], y_ben[hard_index]]))
    probability = second.predict_proba(x_eval)[:, 1]
    print("with hard negatives, evaluated on %d unseen benign" % int((y_eval == 0).sum()))
    evaluate(probability, y_eval, fam_eval)


if __name__ == "__main__":
    main()
