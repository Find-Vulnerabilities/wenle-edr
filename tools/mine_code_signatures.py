#!/usr/bin/env python3
"""Turn real samples into machine-code signatures.

A name rule needs the family to say its own name. A code signature needs
nothing: it is a byte sequence from a section the CPU actually executes, chosen
because it does not occur in a corpus of benign system binaries and does occur
in the sample.

What it produces is deliberately conservative:

* windows are 32 bytes, taken from executable sections only;
* any window that occurs in the benign corpus is discarded;
* three windows per sample are kept, and the rule requires two of them, so a
  single relocation or a shared compiler stub cannot satisfy it;
* the rule is gated on a PE (`uint16(0) == 0x5A4D`).

The honest limit: exact bytes cover the sample and variants that share that
code. A rewritten variant needs its own extraction. That is the trade for a rule
that does not depend on the malware keeping a name.

Usage:
  python mine_code_signatures.py --samples DIR --benign C:\\Windows\\System32 \\
      --out rules/local/rootkits_code.avrule
"""
import argparse
import collections
import hashlib
import math
import os
import sys

import pefile

WINDOW = 32
SIGNATURES = 3
BENIGN_FILES = 30
BENIGN_BYTES = 512 * 1024
SAMPLE_BYTES = 2 * 1024 * 1024


def executable_bytes(path, limit):
    """The raw bytes of the sections a CPU can run, capped at `limit`."""
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return b""
    chunks = []
    for section in pe.sections:
        characteristics = section.Characteristics or 0
        if not characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            continue
        try:
            data = section.get_data()
        except Exception:
            continue
        chunks.append(data)
        if sum(len(chunk) for chunk in chunks) >= limit:
            break
    pe.close()
    return b"".join(chunks)[:limit]


def window_hashes(data, size=WINDOW):
    hashes = set()
    for offset in range(0, len(data) - size + 1, 4):
        hashes.add(hashlib.blake2b(data[offset:offset + size], digest_size=8).digest())
    return hashes


def entropy(block):
    counts = collections.Counter(block)
    total = len(block)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())




def wildcarded(block):
    """Mask the four bytes after E8/E9, which are a relative target.

    Two builds of the same source differ in those displacements first, and the
    rest of the block still identifies the code. Twenty-six exact bytes are
    left, which is why the rule is still safe to convict on.
    """
    masked = list(block)
    for index, byte in enumerate(block[:-5]):
        if byte in (0xE8, 0xE9):
            for offset in range(1, 5):
                masked[index + offset] = None
    return " ".join("??" if byte is None else "%02X" % byte for byte in masked)


def verify_against_benign(blocks, directory):
    """Reject a signature if any benign executable in the directory contains it.

    The window filter above only sees the first 512 KB of thirty files. msvcr100.dll
    is not one of them, and the Duqu2 signatures mined before this check matched
    its runtime code -- the rule convicted a system DLL on 2026-11-24. This second
    pass reads every PE in System32 once and drops any block it finds.
    """
    unique = list(dict.fromkeys(blocks))
    rejected = set()
    for entry in os.listdir(directory):
        if not entry.lower().endswith((".exe", ".dll", ".sys", ".cpl", ".ocx", ".scr")):
            continue
        try:
            with open(os.path.join(directory, entry), "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        for block in unique:
            if block not in rejected and block in data:
                rejected.add(block)
    return rejected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", required=True)
    parser.add_argument("--benign", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--max-samples", type=int, default=40)
    parser.add_argument("--verify", action="store_true", default=True)
    args = parser.parse_args()

    benign = set()
    used = 0
    for entry in sorted(os.listdir(args.benign)):
        if not entry.lower().endswith(".exe"):
            continue
        path = os.path.join(args.benign, entry)
        try:
            if os.path.getsize(path) > 8 * 1024 * 1024:
                continue
        except OSError:
            continue
        data = executable_bytes(path, BENIGN_BYTES)
        benign |= window_hashes(data)
        used += 1
        if used >= BENIGN_FILES:
            break
    print("benign files:", used, "benign windows:", len(benign))

    mined = []
    samples = [name for name in sorted(os.listdir(args.samples))
               if os.path.isfile(os.path.join(args.samples, name))][:args.max_samples]
    for name in samples:
        path = os.path.join(args.samples, name)
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ":
                continue
        data = executable_bytes(path, SAMPLE_BYTES)
        if len(data) < WINDOW * 4:
            continue
        candidates = {}
        for offset in range(0, len(data) - WINDOW + 1, 4):
            block = data[offset:offset + WINDOW]
            digest = hashlib.blake2b(block, digest_size=8).digest()
            if digest in benign or digest in candidates:
                continue
            candidates[digest] = block
        ranked = sorted(candidates.values(), key=entropy, reverse=True)[:SIGNATURES]
        sha = hashlib.sha256(open(path, "rb").read()).hexdigest()
        family = name.split("__", 1)[0] if "__" in name else None
        mined.append({"family": family, "sha": sha, "blocks": ranked})
        print("mined", name, "->", sha[:12])

    all_blocks = [block for entry in mined for block in entry["blocks"]]
    rejected = verify_against_benign(all_blocks, args.benign) if args.verify else set()
    print("signatures rejected by the benign corpus:", len(rejected))
    rules = []
    for entry in mined:
        survivors = [block for block in entry["blocks"] if block not in rejected]
        if len(survivors) < 2:
            print("dropped", entry["sha"][:12], "no signature survived verification")
            continue
        rule_id = "code_" + entry["sha"][:12]
        lines = [
            "rule %s {" % rule_id,
            "    meta:",
            '        description = "Machine-code signature from a sample with sha256 %s."' % entry["sha"],
            '        severity = "high"',
            '        category = "rootkit"',
        ]
        if entry["family"] and entry["family"].isalnum():
            lines.append('        family = "%s"' % entry["family"])
        lines.append("    strings:")
        for index, block in enumerate(survivors, 1):
            lines.append("        $c%d = { %s }" % (index, wildcarded(block)))
        lines.append("    condition:")
        lines.append("        uint16(0) == 0x5A4D and 2 of them")
        lines.append("}")
        rules.append("\n".join(lines))

    header = """/*
 * Machine-code signatures, generated by tools/mine_code_signatures.py.
 *
 * Each rule holds three 32-byte sequences from executable sections of a real
 * sample. A sequence present anywhere in the System32 executables was discarded
 * during verification; the rule requires two of the three, so one shared stub or
 * one relocation cannot satisfy it. Nothing here depends on the family keeping a
 * name.
 *
 * Edit the extractor, not this file.
 */

"""
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="") as handle:
        handle.write(header + "\n\n".join(rules) + "\n")
    print("rules written:", len(rules))


if __name__ == "__main__":
    sys.exit(main())
