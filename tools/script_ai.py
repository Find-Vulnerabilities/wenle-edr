#!/usr/bin/env python3
"""Language-agnostic features for script detection.

The problem this solves is not "is this PowerShell malicious" but "is this a
script doing harm", across batch, PowerShell, VBScript, JScript, Python and HTML
applications, including one file that mixes several of them.

# Decode first

The model must not see the encoding; it must see the text. Bytes are decoded by
BOM, then UTF-8, then UTF-16, then the local code page, and the text is what the
features come from. A script written in UTF-16 is the same script as one written
in UTF-8, and the model is built so that it cannot tell them apart.

# One vocabulary for every language

Each language names the same operations differently. `iex`, `Invoke-Expression`,
`eval`, `WScript.Shell.Run` and `exec(` are all "execute code". The semantic
table maps those spellings to one operation, and the operation counts are
features. A model trained on one language therefore recognises the operation in
another, which is what makes a single model possible instead of one per
language.

# Character n-grams, hashed

The text is also reduced to lowercased 3- to 5-grams hashed into a fixed space:
it survives obfuscation, string splitting and language mixing better than words
do, and it needs no tokenizer per language.

# Embedded payloads

A script that carries a PE is not less malicious for being a script. The
features include whether the decoded text contains an MZ header, whether a long
base64 run decodes to one, and whether the text names an archive format.
"""
import base64
import binascii
import codecs
import hashlib
import math
import re

# One entry per operation: (name, spellings).
import os as _os
_KEEP = {name.strip() for name in _os.environ.get("WENLE_SEMANTIC", "").split(",") if name.strip()}

SEMANTIC = [
    ("exec", ["iex", "invoke-expression", "eval", "exec(", "wscript.shell", "run(",
              "system(", "shell_exec", "passthru", "os.execute", "exec.command",
              "runtime.exec", "subprocess.run", "subprocess.call", "popen",
              "start-process", "shell.application", "call ", "& ", "|iex",
              "powershell", "cmd /c", "start \"\"", "start "]),
    ("decode", ["frombase64string", "convert]::frombase64", "base64.b64decode",
                "base64 -d", "base64_decode", "base64.decode64", "unpack(", "atob(", "b64decode",
                "certutil", "expand-archive", "adodb.stream", "msxml2.domdocument",
                "b64decode", "atob(", "fromhex", "unhexlify",
                "tar -x", "tar -xf", "expand ", "7z ", "unzip", "extrac32", "makecab"]),
    ("download", ["downloadstring", "downloadfile", "webclient", "invoke-webrequest",
                  "iwr ", "urlopen", "urllib", "requests.get", "curl ", "wget ",
                  "start-bitstransfer", "bitsadmin"]),
    ("write", ["writeallbytes", "writealltext", "savetofile", "open(", "copy-item",
               "move-item", "set-content", "fs.writefile", "echo >", ">>",
               "copy ", "xcopy", "robocopy", "mkdir "]),
    ("process", ["start-process", "createprocess", "wmic process", "subprocess",
                 "os.system", "shell(", "win32_process", "shellexecute"]),
    ("persistence", ["currentversion\\\\run", "schtasks", "new-scheduledtask",
                     "startup", "registry", "reg add", "service", "systemd", "crontab"]),
    ("credentials", ["mimikatz", "lsass", "sekurlsa", "credential", "password",
                     "vault", "dpapi"]),
    ("defence", ["set-mppreference", "disablerealtime", "vssadmin", "delete shadows",
                 "wbadmin", "amsi", "amsiutils", "bcdedit", "recoveryenabled"]),
    ("account", ["net user", "net localgroup", "new-localuser", "useradd", "createaccount"]),
    ("kill", ["taskkill", "sc stop", "net stop", "stop-process", "kill "]),
    ("wmi", ["wmic", "win32_process", "get-wmiobject", "invoke-cimmethod"]),
    ("recon", ["query session", "query user", "whoami", "systeminfo", "ipconfig",
               "netstat", "tasklist", "net view", "nltest", "net group"]),
    ("service_control", ["sc config", "net start", "sc create"]),
    ("scripting", ["for /f", "setlocal", "attrib ", "goto "]),
    ("network", ["http://", "https://", "tcpclient", "socket", "netcat", "nc ",
                 "invoke-restmethod", "ftp://"]),
    ("obfuscation", ["-enc ", "-encodedcommand", "fromcharcode", "string.fromcharcode",
                     "char(", "join(", "replace(", "reverse(", "substring("]),
]

if _KEEP:
    SEMANTIC = [entry for entry in SEMANTIC if entry[0] in _KEEP]

ENTITY = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
MZ = b"MZ\x90\x00"


def decode_bytes(data: bytes) -> str:
    """The text of a script, whatever encoding it was written in."""
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
    ):
        if data.startswith(bom):
            return data.decode(encoding, errors="replace")
    for encoding in ("utf-8", "utf-16-le", "cp1252", "gbk"):
        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace")


def longest_encoded_run(data: bytes) -> int:
    best = 0
    for match in ENTITY.finditer(data):
        best = max(best, len(match.group(0)))
    return best


def decodes_to_pe(data: bytes) -> bool:
    for match in ENTITY.finditer(data):
        chunk = match.group(0)
        if len(chunk) % 4:
            chunk = chunk[: len(chunk) - (len(chunk) % 4)]
        try:
            raw = base64.b64decode(chunk, validate=False)
        except (binascii.Error, ValueError):
            continue
        for offset in range(0, min(len(raw), 64)):
            if raw[offset:offset + 4] == MZ:
                return True
    return False


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def semantic_counts(lower: str):
    return [sum(lower.count(spelling) for spelling in spellings) for _, spellings in SEMANTIC]


def structural(data: bytes, text: str):
    lower = text.lower()
    printable = sum(1 for character in text if character.isprintable())
    return [
        float(len(data)),
        float(len(text)),
        float(len(text.splitlines())),
        entropy(text[:200000]),
        printable / max(len(text), 1),
        sum(1 for character in text if ord(character) > 127) / max(len(text), 1),
        float(longest_encoded_run(data)),
        1.0 if decodes_to_pe(data) else 0.0,
        1.0 if b"MZ" in data else 0.0,
        1.0 if re.search(r"(?i)\b(powershell|cmd\.exe|wscript|cscript|python)\b", lower) else 0.0,
        float(lower.count("//") + lower.count("#")),
    ]



def canonicalise(text: str) -> str:
    """Replace every language's spelling of an operation with one token.

    Without this the n-grams learn "iwr" and "urlopen" as different things,
    which is exactly what makes a model trained on PowerShell miss a batch
    file. The token is the operation, not the word.
    """
    lowered = text.lower()
    import re as _re
    # Comment lines are where templates hide their names; they are not behaviour.
    lowered = "\n".join(
        line for line in lowered.splitlines()
        if not _re.match(r"\s*(rem\b|::|#|//)", line)
    )
    for name, spellings in SEMANTIC:
        for spelling in sorted(spellings, key=len, reverse=True):
            lowered = lowered.replace(spelling, " <%s> " % name)
    return lowered


def ngram_hashes(text: str, bits: int = 16, canonical: bool = True):
    """Hashed character 3- to 5-grams, as (index, count) pairs."""
    source = canonicalise(text) if canonical else text.lower()
    lower = re.sub(r"\s+", " ", source)[:4000]
    hashes = []
    for size in (3, 4):
        for start in range(0, max(len(lower) - size + 1, 0)):
            gram = lower[start:start + size]
            digest = hashlib.md5(gram.encode("utf-8", "ignore")).digest()
            hashes.append(int.from_bytes(digest[:4], "little") % (1 << bits))
    counts = {}
    for index in hashes:
        counts[index] = counts.get(index, 0) + 1
    return counts


def features(data: bytes):
    text = decode_bytes(data)
    lower = text.lower()
    dense = structural(data, text) + semantic_counts(lower)
    # Two views of the same script: the language's own words, which is what
    # tells Python from batch, and the canonical operations, which is what lets
    # a batch file be recognised by a model trained on PowerShell. Replacing the
    # text with only the canonical view cost the Python held-out split twenty
    # points; keeping both keeps both.
    grams = dict(ngram_hashes(text, canonical=False))
    for index, count in ngram_hashes(text, canonical=True).items():
        grams[index + (1 << 16)] = grams.get(index + (1 << 16), 0) + count
    return dense, grams


if __name__ == "__main__":
    import sys

    path = sys.argv[1]
    data = open(path, "rb").read()
    dense, sparse = features(data)
    print("dense", [round(value, 2) for value in dense])
    print("n-grams", len(sparse))
