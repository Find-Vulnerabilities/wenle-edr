#!/usr/bin/env python3
"""Turn a Speakeasy report into findings this product understands.

Speakeasy emulates the sample and records what it asked Windows to do. That
record is the same kind of evidence the behaviour story model consumes from the
driver, so it is mapped onto the same families: environment probing, process
enumeration, code injection, persistence, process creation, download, defence
tampering, and file writes.

The output is one JSON document per sample:

    {"sample": ..., "sha256": ..., "score": 0.0-1.0, "findings": [...]}

Usage: python tools/sandbox_analyze.py --report report.json [--out findings.json]
"""
import argparse
import json
import re

# One family per group of API names. The match is on the API name Speakeasy
# recorded, case-insensitively, and a family fires once however many calls it
# took: the question is whether the behaviour happened, not how often.
FAMILIES = {
    "environment_probe": [
        "getsy stemmetrics", "getsystemmetrics", "gettickcount", "queryperformancecounter",
        "globalmemorystatus", "getcomputername", "getusername", "getversionex",
        "getsysteminfo", "getvolumeinformation", "getadaptersinfo", "getlocaltime",
        "gettimezoneinformation", "systemtimeasfiletime",
    ],
    "anti_analysis": [
        "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
        "outputdebugstring", "findwindow", "getforegroundwindow", "enumwindows",
        "setunhandledexceptionfilter", "queryperformancefrequency",
    ],
    "process_enum": [
        "createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses",
        "enumprocessmodules", "getprocessimagefilename",
    ],
    "injection": [
        "virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection",
        "setthreadcontext", "queueuserapc", "ntunmapviewofsection", "virtualprotectex",
    ],
    "persistence": [
        "regsetvalue", "regcreatekey", "createservice", "openscmanager",
        "schtasks", "createscheduledtask", "writefile",
    ],
    "process_creation": [
        "createprocess", "shellexecute", "winexec", "system",
    ],
    "download": [
        "internetopen", "internetsetoption", "httpsendrequest", "urldownloadtofile",
        "winhttpopen", "winhttpsendrequest", "wsastartup", "wsaconnect", "socket",
        "connect", "send", "recv", "getaddrinfo", "dnsquery",
    ],
    "defence_tampering": [
        "setmppreference", "deletefile", "regdeletekey", "regdeletevalue",
        "terminateprocess", "ntterminateprocess",
    ],
    "credential_access": [
        "lsass", "mimikatz", "credread", "credential", "cryptunprotectdata",
    ],
    "file_write": [
        "createfile", "writefile", "copyfile", "movefile", "setfileattributes",
    ],
}

SEVERITY = {
    "injection": 0.9,
    "defence_tampering": 0.85,
    "credential_access": 0.9,
    "download": 0.6,
    "persistence": 0.6,
    "process_creation": 0.5,
    "environment_probe": 0.25,
    "anti_analysis": 0.4,
    "process_enum": 0.3,
    "file_write": 0.2,
}


def events_of(report):
    for run in report.get("runs") or []:
        for event in run.get("events") or []:
            if event.get("event") == "api":
                yield event


def analyse(report):
    seen = {}
    for event in events_of(report):
        name = (event.get("api_name") or "").lower().replace("!", ".")
        short = name.split(".")[-1]
        for family, needles in FAMILIES.items():
            if any(needle in short or needle in name for needle in needles):
                entry = seen.setdefault(family, {"calls": 0, "examples": []})
                entry["calls"] += 1
                if len(entry["examples"]) < 5 and event.get("api_name") not in entry["examples"]:
                    entry["examples"].append(event.get("api_name"))

    findings = []
    score = 0.0
    for family, entry in sorted(seen.items(), key=lambda item: -SEVERITY.get(item[0], 0.1)):
        weight = SEVERITY.get(family, 0.1)
        score = max(score, weight)
        findings.append({
            "family": family,
            "severity": weight,
            "calls": entry["calls"],
            "examples": entry["examples"],
            "description": "%s: %d call(s), e.g. %s" % (
                family, entry["calls"], ", ".join(entry["examples"])),
        })
    # Three weak families together are stronger than any one of them.
    if len(findings) >= 3:
        score = min(1.0, score + 0.1)
    return score, findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    with open(args.report, encoding="utf-8") as handle:
        report = json.load(handle)
    score, findings = analyse(report)
    document = {
        "sample": report.get("path"),
        "sha256": report.get("sha256"),
        "score": round(score, 3),
        "findings": findings,
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=1)
    print(json.dumps(document, indent=1))


if __name__ == "__main__":
    main()
