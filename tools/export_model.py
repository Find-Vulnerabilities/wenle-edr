#!/usr/bin/env python3
"""Convert a LightGBM text model into the flat binary the Rust engine reads.

Format (little endian):

    magic   u32   0x57414931 ("WAI1")
    trees   u32
    features u32
    per tree:
        leaves  u32
        split_feature  i32 * (leaves - 1)
        threshold      f32 * (leaves - 1)
        left_child     i32 * (leaves - 1)
        right_child    i32 * (leaves - 1)
        leaf_value     f32 * leaves

A negative child index encodes a leaf: leaf = -child - 1. Splits are
`feature <= threshold` going left, matching LightGBM's default.
"""
import struct
import sys


def parse_arrays(text):
    trees = []
    current = {}
    for line in text.splitlines():
        if line.startswith("Tree="):
            if current:
                trees.append(current)
            current = {}
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in ("num_leaves", "split_feature", "threshold", "left_child",
                   "right_child", "leaf_value", "decision_type"):
            current[key] = value
    if current:
        trees.append(current)
    return trees


def numbers(value):
    if not value.strip():
        return []
    return [item for item in value.strip().split() if item]


def main():
    source, target = sys.argv[1], sys.argv[2]
    with open(source, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    trees = parse_arrays(text)
    features = 0
    payload = bytearray()
    for tree in trees:
        leaves = int(tree["num_leaves"])
        split = [int(item) for item in numbers(tree["split_feature"])]
        threshold = [float(item) for item in numbers(tree["threshold"])]
        left = [int(item) for item in numbers(tree["left_child"])]
        right = [int(item) for item in numbers(tree["right_child"])]
        values = [float(item) for item in numbers(tree["leaf_value"])]
        assert len(split) == leaves - 1, (len(split), leaves)
        assert len(threshold) == leaves - 1
        assert len(left) == leaves - 1
        assert len(right) == leaves - 1
        assert len(values) == leaves, (len(values), leaves)
        features = max(features, max(split) + 1 if split else 0)
        payload += struct.pack("<I", leaves)
        payload += struct.pack("<%di" % len(split), *split)
        payload += struct.pack("<%df" % len(threshold), *threshold)
        payload += struct.pack("<%di" % len(left), *left)
        payload += struct.pack("<%di" % len(right), *right)
        payload += struct.pack("<%df" % len(values), *values)
    with open(target, "wb") as handle:
        handle.write(struct.pack("<III", 0x57414931, len(trees), features))
        handle.write(payload)
    print("trees %d, features %d, %.1f MB -> %s"
          % (len(trees), features, (len(payload) + 12) / 1024 / 1024, target))


if __name__ == "__main__":
    sys.exit(main())
