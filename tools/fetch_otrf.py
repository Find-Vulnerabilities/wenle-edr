#!/usr/bin/env python3
"""Download every Windows host capture OTRF publishes and convert it.

The measured transfer from twelve captures was 0.2 %, and the reason is not that
public captures are useless but that twelve is a sample of twelve. This walks
every category OTRF publishes for Windows -- execution, defence evasion,
discovery, credential access, lateral movement, persistence, privilege
escalation, collection -- downloads the host captures, converts them to the
feature space the service serves, and writes one array.

The conversion is `sysmon_to_features.convert`, the same function the earlier
experiment used; what changes is the amount.

Usage:
    python tools/fetch_otrf.py [--out target/sysmon-all.npz] [--max-mb 12]
"""

import argparse
import io
import json
import os
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sysmon_to_features import convert  # noqa: E402

API = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/%s?recursive=1"
RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/%s"

# The category trees, from the repository's `datasets/atomic/windows` listing.
CATEGORIES = {
    "collection": "742fb82120f4451810aeba5fece028eaee7186bf",
    "credential_access": "3667047ddb4d41c015fa98633b6ccc2d40a74629",
    "defense_evasion": "3d69b19a3fdd4d11bd0512bf0ba4e95e3ea2bd98",
    "discovery": "de2de066c3779f81cad1a301d450a8206ea2fc52",
    "execution": "2484ecb5b1db40e00b1761d0a2f54e03809c604b",
    "lateral_movement": "98160b12b44e4ed6bdce7bd0c35888481ced04a1",
    "persistence": "c89efa45d4458adbf9cbad72c56ad0a94dc89893",
    "privilege_escalation": "e648f79d172952a7d002d223a1b344952f13b3ee",
    "other": "c4093b867f78b81a8e96964ed8801c176498e1d7",
}


def fetch(url, timeout=60):
    request = urllib.request.Request(url, headers={"User-Agent": "wenle-av-behaviour"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def list_host_captures(category, tree_sha, max_bytes):
    tree = json.loads(fetch(API % tree_sha).decode("utf-8"))
    out = []
    for entry in tree.get("tree", []):
        path = entry.get("path", "")
        if not path.startswith("host/"):
            continue
        if not path.lower().endswith((".zip", ".tar.gz")):
            continue
        if entry.get("size", 0) > max_bytes:
            continue
        # The tree API returns paths relative to the category, so the category
        # has to be put back for the raw URL. Missing it produced forty 404s per
        # category and a corpus of zero -- measured on 2026-11-15.
        out.append(("datasets/atomic/windows/%s/%s" % (category, path), entry.get("size", 0)))
    return out


def sequences_of(blob, name, work):
    folder = tempfile.mkdtemp(dir=work)
    path = os.path.join(folder, name)
    with open(path, "wb") as handle:
        handle.write(blob)
    try:
        if name.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as handle:
                handle.extractall(folder)
        else:
            with tarfile.open(path, "r:gz") as handle:
                handle.extractall(folder)
    except (zipfile.BadZipFile, tarfile.TarError, OSError):
        return []
    found = []
    for root, _dirs, files in os.walk(folder):
        for file_name in files:
            if file_name.lower().endswith(".json"):
                found.extend(convert(os.path.join(root, file_name)))
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="target/sysmon-all.npz")
    parser.add_argument("--max-mb", type=float, default=12.0)
    parser.add_argument("--per-category", type=int, default=40)
    args = parser.parse_args()
    max_bytes = int(args.max_mb * 1024 * 1024)

    all_sequences = []
    with tempfile.TemporaryDirectory() as work:
        for category, sha in CATEGORIES.items():
            try:
                captures = list_host_captures(category, sha, max_bytes)
            except Exception as error:  # network is external; report and go on
                print("%-22s listing failed: %s" % (category, error))
                continue
            captures = captures[: args.per_category]
            count = 0
            for path, size in captures:
                try:
                    blob = fetch(RAW % path)
                except Exception:
                    continue
                found = sequences_of(blob, os.path.basename(path), work)
                all_sequences.extend(found)
                count += len(found)
            print("%-22s %2d captures -> %4d sequences" % (category, len(captures), count))

    print("total sequences: %d" % len(all_sequences))
    if not all_sequences:
        return 1
    x = np.array(all_sequences, dtype=np.float32)
    np.savez_compressed(args.out, x=x, y=np.ones(len(x), dtype=np.float32),
                        family=np.array(["public"] * len(x)))
    print("wrote %s: %s" % (args.out, x.shape))
    return 0


if __name__ == "__main__":
    sys.exit(main())
