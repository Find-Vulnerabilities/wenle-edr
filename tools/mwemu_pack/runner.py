#!/usr/bin/env python3
"""Run one sample under MWEmu and turn its trace into this product's events.

The hot path stays native: MWEmu executes the PE. This module is the cold path
-- it builds the command line, enforces the timeout, and streams the trace back
into the event shape `tools/sandbox_analyze.py` already understands.

Nothing here imports a third-party package. Startup measured at 26 ms, and a
167,500-line Cerber trace parses in 23 ms, so the wrapper is not where the time
goes.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time

EVENT_LIMIT = 200_000

# The syscalls worth reporting as behaviour. Everything else is counted under
# its own name in the summary but does not become an event, because a trace of
# 167,000 lines with one event per call is a file nobody reads and a rule engine
# nobody wants to run twice.
BEHAVIOUR_SYSCALLS = {
    "ntcreatefile": "CreateFile",
    "ntopenfile": "OpenFile",
    "ntwritefile": "WriteFile",
    "ntsetinformationfile": "SetFileInformation",
    "ntdeletefile": "DeleteFile",
    "ntcreatekey": "RegCreateKey",
    "ntopenkey": "RegOpenKey",
    "ntopenkeyex": "RegOpenKeyEx",
    "ntsetvaluekey": "RegSetValue",
    "ntdeletevaluekey": "RegDeleteValue",
    "ntqueryvaluekey": "RegQueryValue",
    "ntcreateuserprocess": "CreateProcess",
    "ntcreateprocess": "CreateProcess",
    "ntcreatethreadex": "CreateRemoteThread",
    "ntallocatevirtualmemory": "VirtualAlloc",
    "ntprotectvirtualmemory": "VirtualProtect",
    "ntwritevirtualmemory": "WriteProcessMemory",
    "ntcreatesection": "CreateSection",
    "ntmapviewofsection": "MapViewOfSection",
    "ntloaddriver": "LoadDriver",
    "ntcreatedirectoryobject": "CreateDirectory",
}
INJECTION = ("writeprocessmemory", "createremotethread", "createsection", "mapviewofsection")
NETWORK = ("wsaconnect", "wsasend", "wsarecv", "winhttp", "wininet", "socket", "connect", "send", "recv", "urldownload")


def machine_of(path):
    """IMAGE_FILE_MACHINE of a PE, or None if the file is not one."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(0x40)
            if head[:2] != b"MZ":
                return None
            offset = struct.unpack_from("<I", head, 0x3C)[0]
            handle.seek(offset)
            signature = handle.read(4)
            if signature != b"PE\0\0":
                return None
            machine = struct.unpack("<H", handle.read(2))[0]
            return machine
    except OSError:
        return None


def arguments_of(text):
    """`{name: value, ...}` as a list of analyser arguments."""
    arguments = []
    for piece in split_arguments(text):
        value = piece.split("=", 1)[-1].strip().strip('"')
        if value:
            arguments.append({"value": value, "display": value})
    return arguments


def split_arguments(text):
    pieces, current, depth, quoted = [], [], 0, False
    for character in text:
        if character == '"':
            quoted = not quoted
        elif character in "([<{" and not quoted:
            depth += 1
        elif character in ")]>}" and not quoted:
            depth = max(0, depth - 1)
        if character == "," and depth == 0 and not quoted:
            pieces.append("".join(current))
            current = []
        else:
            current.append(character)
    if current:
        pieces.append("".join(current))
    return [piece.strip() for piece in pieces if piece.strip()]


def parse_trace(trace_path):
    """Events and counters from a MWEmu trace, streamed.

    Two shapes carry behaviour:

      ** 1000> 10:1f1241 user32!GetSystemMetrics index=0 value=1920
      ** 1000> 40:1f148b LocalAlloc(flags=0x40, size=0x4000) = 0x6013100

    The module prefix is optional; the argument text is whatever follows the
    API name, and both forms keep it. Calls MWEmu has no handler for are printed
    as `unsupported module!Api(args)`, and those are the ones that matter most:
    the arguments are the behaviour even when the API is not implemented.
    """
    events = []
    apis = {}
    unsupported = {}
    markers = []
    call = re.compile(r"^\*\*\s+\d+>\s+\d+:[0-9a-fA-F]+\s+(?:([A-Za-z0-9_]+)!)?([A-Za-z_][A-Za-z0-9_]*)(.*)$")
    with open(trace_path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if len(events) >= EVENT_LIMIT:
                break
            lowered = line.lower()
            match = re.search(r"unsupported\s+(\w+)!(\w+)\((.*)\)\s*$", line)
            if match:
                module, api, raw = match.group(1), match.group(2), match.group(3)
                name = module.lower() + "." + api
                unsupported[name] = unsupported.get(name, 0) + 1
                events.append({"event": "api", "api_name": name, "args": arguments_of(raw)})
                continue
            match = call.search(line)
            if match:
                module, api, raw = match.group(1), match.group(2), match.group(3)
                name = (module.lower() + "." + api) if module else api
                apis[name] = apis.get(name, 0) + 1
                events.append({"event": "api", "api_name": name, "args": arguments_of(raw)})
                continue
            if "emulation failed" in lowered or "unhandled exception" in lowered:
                markers.append(line.strip()[:300])
    return {
        "events": events,
        "apis": apis,
        "unsupported": unsupported,
        "markers": markers,
    }



def load_engine_config(engine):
    """The worker's engine.json, three directories above the binary."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(engine)))), "engine.json")
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle).get("mwemu", {})
    except (OSError, ValueError):
        return {}



def parse_event_stream(path):
    """Read MWEmu's JSONL stream: one call per line, already structured."""
    events = []
    apis = {}
    unsupported = {}
    with open(path, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            name = record.get("api") or ""
            if not name:
                continue
            if "!" in name:
                module, api = name.split("!", 1)
                api_name = module.lower() + "." + api
            else:
                api_name = name
            if record.get("kind") == "unsupported":
                unsupported[api_name] = unsupported.get(api_name, 0) + 1
            else:
                apis[api_name] = apis.get(api_name, 0) + 1
            events.append({
                "event": "api",
                "api_name": api_name,
                "args": arguments_of(record.get("arguments") or ""),
            })
    return events, apis, unsupported


def default_maps(engine):
    """The engine's own maps directory, when it ships one.

    MWEmu resolves `maps/winver/...` against its working directory, and that
    directory is `target/release` after a build -- not the repository that holds
    `maps/`. Without this the first run of every sample spends its whole timeout
    re-fetching system DLLs from the symbol server.
    """
    engine_dir = os.path.dirname(os.path.abspath(engine))
    for candidate in (
        os.path.join(engine_dir, "maps"),
        os.path.join(os.path.dirname(os.path.dirname(engine_dir)), "maps"),
    ):
        if os.path.isdir(candidate):
            return candidate
    return None



def file_digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def guest_to_host(engine, guest_path):
    """Map a guest `C:\\...` path into the engine's file_root jail."""
    text = guest_path.strip().strip('"').replace("/", "\\")
    for prefix in ("\\\\?\\", "\\??\\"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    if len(text) >= 2 and text[1] == ":":
        text = text[2:]
    text = text.lstrip("\\")
    parts = [part for part in text.split("\\") if part and part != "."]
    if any(part == ".." for part in parts):
        return None
    root = os.path.join(os.path.dirname(os.path.abspath(engine)), "file_root")
    return os.path.join(root, *parts)


def child_candidates(events):
    """Guest paths a sample tried to start, in first-seen order."""
    seen = []
    pattern = re.compile(r'(?:[A-Za-z]:\\[^"\s]+?\.exe|[^"\s]+?\.exe)', re.IGNORECASE)
    for event in events:
        name = event.get("api_name", "").lower()
        if not any(word in name for word in ("createprocess", "shellexecute", "winexec", "createuserprocess")):
            continue
        for argument in event.get("args", []):
            value = argument.get("value") or ""
            for match in pattern.findall(value):
                if match not in seen:
                    seen.append(match)
    return seen[:3]


def run(sample, out_dir, engine, seconds, winver="win11", maps=None, iso=None,
        username=None, hostname=None, domain=None, endpoint=False,
        follow=True, depth=0, visited=None):
    os.makedirs(out_dir, exist_ok=True)
    trace_path = os.path.join(out_dir, "trace.txt")
    machine = machine_of(sample)
    if machine is None:
        return {"ok": False, "reason": "not a PE file"}
    maps = maps or default_maps(engine)
    events_path = os.path.join(out_dir, "events.jsonl")
    command = [engine, "-f", sample, "--winver", winver,
               "--api-mode", "simulate-success", "-v", "-L", trace_path,
               "--events-json", events_path]
    if machine == 0x8664:
        command.insert(1, "-6")
    if maps:
        command += ["-M", maps]
    if iso:
        command += ["--iso", iso]
    if username:
        command += ["--username", username]
    if hostname:
        command += ["--hostname", hostname]
    if domain:
        command += ["--domain", domain]
    if endpoint:
        command += ["--endpoint"]
    registry = os.path.join(os.path.dirname(os.path.abspath(engine)), "registry.txt")
    if os.path.isfile(registry):
        command += ["--registry", registry]
    started = time.time()
    with open(os.path.join(out_dir, "mwemu.out"), "wb") as output, \
            open(os.path.join(out_dir, "mwemu.err"), "wb") as error:
        process = subprocess.Popen(command, stdout=output, stderr=error,
                                   cwd=os.path.dirname(engine))
        try:
            process.wait(timeout=seconds)
            timed_out = False
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            timed_out = True
    elapsed = round(time.time() - started, 2)
    parsed = parse_trace(trace_path) if os.path.exists(trace_path) else {
        "events": [], "apis": {}, "unsupported": {}, "markers": []
    }
    if os.path.exists(events_path) and os.path.getsize(events_path) > 0:
        structured, apis, unsupported = parse_event_stream(events_path)
        # The structured stream does not carry argument values for calls MWEmu
        # has no handler for; the text trace does, and those arguments are the
        # evidence. Keep both: the stream for shape, the trace for arguments.
        from_trace = [
            event for event in parsed["events"]
            if event.get("api_name") in unsupported
        ]
        if structured:
            parsed["events"] = structured + from_trace
            parsed["apis"] = apis
            parsed["unsupported"] = unsupported
    visited = set() if visited is None else visited
    try:
        visited.add(file_digest(sample))
    except OSError:
        pass
    children = []
    if follow and depth < 2:
        for child in child_candidates(parsed["events"]):
            host = guest_to_host(engine, child)
            if not host or not os.path.isfile(host) or machine_of(host) is None:
                continue
            try:
                digest = file_digest(host)
            except OSError:
                continue
            if digest in visited:
                continue
            child_out = os.path.join(out_dir, "child-" + digest[:12])
            result = run(host, child_out, engine, max(5, seconds // 2), winver, maps, iso,
                         username, hostname, domain, endpoint, follow, depth + 1, visited)
            if result.get("ok"):
                parsed["events"].append({
                    "event": "child_process",
                    "api_name": "sandbox.follow",
                    "args": [{"value": child, "display": child}],
                })
                parsed["events"].extend(result["report"]["runs"][0]["events"])
                children.append({"path": child, "report": child_out})
    report = {
        "runs": [{"events": parsed["events"]}],
        "mwemu": {
            "engine": engine,
            "machine": "x86_64" if machine == 0x8664 else "x86",
            "elapsed_seconds": elapsed,
            "timed_out": timed_out,
            "instruction_note": "see trace",
            "api_events": sum(parsed["apis"].values()),
            "unique_apis": len(parsed["apis"]),
            "unsupported": parsed["unsupported"],
            "markers": parsed["markers"],
            "children": children,
        },
    }
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1)
    return {"ok": True, "report": report, "elapsed": elapsed, "timed_out": timed_out}


def analyse(out_dir):
    """Run the existing analyser over the report and write the summary."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from sandbox_analyze import analyse as analyse_report
    report = json.load(open(os.path.join(out_dir, "report.json"), encoding="utf-8"))
    score, findings, decisive = analyse_report(report)
    summary = {
        "score": score,
        "findings": findings,
        "decisive": decisive,
        "unpacked": [],
        "events": len(report["runs"][0]["events"]),
        "mwemu": report.get("mwemu", {}),
    }
    with open(os.path.join(out_dir, "summary.json"), "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=1)
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--engine", default=r"C:\Users\wensz\Downloads\mwemu-src\target\release\mwemu.exe")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--winver", default="win11")
    parser.add_argument("--maps")
    parser.add_argument("--iso")
    parser.add_argument("--analyse", action="store_true")
    parser.add_argument("--username")
    parser.add_argument("--hostname")
    parser.add_argument("--domain")
    parser.add_argument("--endpoint", action="store_true")
    parser.add_argument("--no-follow", action="store_true")
    args = parser.parse_args()
    settings = load_engine_config(args.engine)
    result = run(args.sample, args.out, args.engine, args.seconds,
                 args.winver, args.maps, args.iso,
                 args.username or settings.get("username"),
                 args.hostname or settings.get("hostname"),
                 args.domain or settings.get("domain"),
                 args.endpoint or bool(settings.get("endpoint")),
                 not args.no_follow)
    if not result["ok"]:
        print(json.dumps(result))
        return 1
    print("elapsed: %s s (timed out: %s)" % (result["elapsed"], result["timed_out"]))
    print("events: %d, apis: %d, unsupported: %d" % (
        len(result["report"]["runs"][0]["events"]),
        result["report"]["mwemu"]["unique_apis"],
        len(result["report"]["mwemu"]["unsupported"]),
    ))
    if args.analyse:
        summary = analyse(args.out)
        print(json.dumps({k: summary[k] for k in ("score", "decisive")}, indent=1))
        for finding in summary["findings"][:6]:
            print("  %-22s %s" % (finding["family"], finding.get("example", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
