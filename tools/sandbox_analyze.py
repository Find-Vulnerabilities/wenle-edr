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

    decisive = decisive_behaviours(report)
    return score, findings, decisive


def argument_text(event):
    """Every argument value of one API call, joined for pattern matching."""
    parts = []
    for argument in event.get("args") or []:
        value = argument.get("value")
        display = argument.get("display")
        for candidate in (display, value):
            if isinstance(candidate, str):
                parts.append(candidate)
    return " ".join(parts).lower()


def decisive_behaviours(report):
    """The four behaviours this product stops on, seen in an emulation.

    These are the decisive detectors the behaviour engine already trusts on the
    driver: a ransomware shape, a known driver-loading tool, a credential tool,
    and an event-log clear. A sandbox run that reaches one of them is stronger
    evidence than any score, and it convicts.
    """
    hits = []
    for event in events_of(report):
        api = (event.get("api_name") or "").lower()
        text = argument_text(event)
        both = api + " " + text
        if any(word in both for word in ("vssadmin", "delete shadows", "wbadmin", "bcdedit")):
            hits.append("ransomware-shape")
        if any(word in both for word in ("lsass", "mimikatz", "sekurlsa", "credential")):
            hits.append("credential-tool")
        if any(word in both for word in ("wevtutil", "cleareventlog", "clear-eventlog")):
            hits.append("event-log-clear")
        if ".sys" in both and any(word in both for word in ("createservice", "startservice", "ntloaddriver")):
            hits.append("byovd-driver")
    # Same order, no duplicates.
    result = []
    for hit in hits:
        if hit not in result:
            result.append(hit)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", required=True)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    with open(args.report, encoding="utf-8") as handle:
        report = json.load(handle)
    score, findings, decisive = analyse(report)
    document = {
        "sample": report.get("path"),
        "sha256": report.get("sha256"),
        "score": round(score, 3),
        "findings": findings,
        "decisive": decisive,
    }
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=1)
    print(json.dumps(document, indent=1))


if __name__ == "__main__":
    main()
