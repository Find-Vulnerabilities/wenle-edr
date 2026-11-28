//! Native orchestrator for the patched MWEmu engine.
//!
//! This replaces `tools/mwemu_pack/runner.py` and the PowerShell worker. The
//! execution engine is still the product's patched `mwemu.exe` (custom APIs,
//! registry, endpoint and real-environment flags); this binary only builds its
//! command line, enforces the timeout, parses the two trace formats, follows
//! child processes inside the engine's file-root jail, and applies the same
//! API-family/decisive analysis the Python worker used.
//!
//! No Python, no pip, no PowerShell is involved in a run.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const EVENT_LIMIT: usize = 200_000;

#[derive(Clone, Debug)]
struct Engine {
    binary: PathBuf,
    winver: String,
    seconds: u64,
    username: Option<String>,
    hostname: Option<String>,
    domain: Option<String>,
    endpoint: bool,
    registry: Option<PathBuf>,
    maps: Option<PathBuf>,
}

impl Engine {
    fn directory(&self) -> PathBuf {
        self.binary.parent().unwrap_or(Path::new(".")).to_path_buf()
    }

    fn file_root(&self) -> PathBuf {
        self.directory().join("file_root")
    }
}

fn main() {
    let mut sample = None;
    let mut out = None;
    let mut seconds = None;
    let mut queue = false;
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--sample" => sample = args.next().map(PathBuf::from),
            "--out" => out = args.next().map(PathBuf::from),
            "--seconds" => seconds = args.next().and_then(|value| value.parse().ok()),
            "--queue" => queue = true,
            "--once" => once = true,
            "--help" | "-h" => {
                println!("wenle-mwemu --sample FILE --out DIR [--seconds N]");
                println!("wenle-mwemu --queue [--seconds N]");
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }
    let engine = load_engine();
    if queue || once {
        run_queue(&engine, seconds, once);
        return;
    }
    let Some(sample) = sample else {
        eprintln!("--sample is required");
        std::process::exit(2);
    };
    let out = out.unwrap_or_else(|| std::env::temp_dir().join("wenle-mwemu"));
    let seconds = seconds.unwrap_or(engine.seconds);
    match run_one(&sample, &out, &engine, seconds, 0, &mut HashSet::new()) {
        Ok(summary) => println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default()),
        Err(error) => {
            eprintln!("sandbox failed: {error}");
            std::process::exit(1);
        }
    }
}

fn sandbox_root() -> PathBuf {
    if let Some(root) = std::env::var_os("WENLE_SANDBOX_DIR") {
        return PathBuf::from(root);
    }
    PathBuf::from(r"C:\ProgramData\WenleAV\sandbox")
}

fn load_engine() -> Engine {
    let root = sandbox_root();
    let mut binary = root.join(r"mwemu\bin\mwemu.exe");
    let mut winver = "win11".to_string();
    let mut seconds = 30u64;
    let mut username = Some("wenle".to_string());
    let mut hostname = Some("DESKTOP-7F3A9C2".to_string());
    let mut domain = Some("WORKGROUP".to_string());
    let mut endpoint = false;
    let mut registry = None;
    let mut maps = None;
    if let Ok(text) = std::fs::read_to_string(root.join("engine.json")) {
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            if let Some(section) = value.get("mwemu") {
                if let Some(path) = section.get("binary").and_then(|value| value.as_str()) {
                    binary = PathBuf::from(path);
                }
                if let Some(value) = section.get("winver").and_then(|value| value.as_str()) {
                    winver = value.to_string();
                }
                if let Some(value) = section.get("seconds").and_then(|value| value.as_u64()) {
                    seconds = value;
                }
                username = section.get("username").and_then(|value| value.as_str()).map(str::to_string);
                hostname = section.get("hostname").and_then(|value| value.as_str()).map(str::to_string);
                domain = section.get("domain").and_then(|value| value.as_str()).map(str::to_string);
                endpoint = section.get("endpoint").and_then(|value| value.as_bool()).unwrap_or(false);
                registry = section.get("registry").and_then(|value| value.as_str()).map(PathBuf::from);
            }
        }
    }
    if let Ok(path) = std::env::var("WENLE_MWEMU_ENGINE") {
        binary = PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("WENLE_MWEMU_MAPS") {
        maps = Some(PathBuf::from(path));
    }
    let dir = binary.parent().unwrap_or(Path::new(".")).to_path_buf();
    let maps = maps.or_else(|| {
        let candidate = dir.join("maps");
        candidate.is_dir().then_some(candidate)
    });
    let registry = registry.or_else(|| {
        let candidate = dir.join("registry.txt");
        candidate.is_file().then_some(candidate)
    });
    Engine { binary, winver, seconds, username, hostname, domain, endpoint, registry, maps }
}

fn run_queue(engine: &Engine, seconds: Option<u64>, once: bool) {
    let root = sandbox_root();
    let queue = root.join("queue");
    let results = root.join("results");
    let done = root.join("done");
    let failed = root.join("failed");
    for dir in [&results, &done, &failed] {
        let _ = std::fs::create_dir_all(dir);
    }
    loop {
        let jobs: Vec<PathBuf> = std::fs::read_dir(&queue)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| path.extension().is_some_and(|ext| ext == "job"))
                    .collect()
            })
            .unwrap_or_default();
        // Drain the whole snapshot. The old five-job cap let a queue of 200
        // take forty task runs to clear; every PE is queued now, so a cap
        // would turn the queue into the place analysis goes to die.
        for job in jobs.into_iter() {
            let name = job.file_name().map(PathBuf::from).unwrap_or_default();
            let Ok(body) = std::fs::read_to_string(&job) else {
                let _ = std::fs::rename(&job, failed.join(&name));
                continue;
            };
            let mut lines = body.lines();
            let Some(sample) = lines.next().map(PathBuf::from) else {
                let _ = std::fs::rename(&job, failed.join(&name));
                continue;
            };
            let Some(sha) = lines.next().map(str::trim).filter(|value| !value.is_empty()) else {
                let _ = std::fs::rename(&job, failed.join(&name));
                continue;
            };
            if !sample.is_file() {
                let _ = std::fs::rename(&job, failed.join(&name));
                continue;
            }
            let out = results.join(format!("run-{sha}"));
            let seconds = seconds.unwrap_or(engine.seconds);
            match run_one(&sample, &out, engine, seconds, 0, &mut HashSet::new()) {
                Ok(summary) => {
                    if let Err(error) = std::fs::write(
                        results.join(format!("{sha}.json")),
                        serde_json::to_string_pretty(&summary).unwrap_or_default(),
                    ) {
                        eprintln!("could not cache {sha}: {error}");
                    }
                    let _ = std::fs::rename(&job, done.join(&name));
                }
                Err(error) => {
                    eprintln!("sandbox {} failed: {error}", sample.display());
                    let _ = std::fs::rename(&job, failed.join(&name));
                }
            }
        }
        if once {
            return;
        }
        std::thread::sleep(Duration::from_secs(15));
    }
}

fn run_one(
    sample: &Path,
    out: &Path,
    engine: &Engine,
    seconds: u64,
    depth: usize,
    visited: &mut HashSet<String>,
) -> Result<Value, String> {
    std::fs::create_dir_all(out).map_err(|error| error.to_string())?;
    let raw = std::fs::read(sample).map_err(|error| format!("read: {error}"))?;
    let sha = hex::encode(Sha256::digest(&raw));
    let machine = machine_of(&raw).ok_or_else(|| "not a PE image".to_owned())?;
    visited.insert(sha.clone());
    let trace_path = out.join("trace.txt");
    let events_path = out.join("events.jsonl");
    let mut command = Command::new(&engine.binary);
    if machine == 0x8664 {
        command.arg("-6");
    }
    command
        .arg("-f").arg(sample)
        .arg("--winver").arg(&engine.winver)
        .arg("--api-mode").arg("simulate-success")
        .arg("-v")
        .arg("-L").arg(&trace_path)
        .arg("--events-json").arg(&events_path);
    if let Some(maps) = &engine.maps {
        command.arg("-M").arg(maps);
    }
    if let Some(username) = &engine.username {
        command.arg("--username").arg(username);
    }
    if let Some(hostname) = &engine.hostname {
        command.arg("--hostname").arg(hostname);
    }
    if let Some(domain) = &engine.domain {
        command.arg("--domain").arg(domain);
    }
    if engine.endpoint {
        command.arg("--endpoint");
    }
    if let Some(registry) = &engine.registry {
        command.arg("--registry").arg(registry);
    }
    let stdout = std::fs::File::create(out.join("mwemu.out")).map_err(|error| error.to_string())?;
    let stderr = std::fs::File::create(out.join("mwemu.err")).map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut child = command
        .current_dir(engine.directory())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("spawn: {error}"))?;
    let deadline = started + Duration::from_secs(seconds);
    let mut timed_out = false;
    loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                timed_out = true;
                break;
            }
            None => std::thread::sleep(Duration::from_millis(40)),
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    let parsed = parse_trace(&trace_path);
    let mut events = parsed.events;
    let mut apis = parsed.apis;
    let mut unsupported = parsed.unsupported;
    let markers = parsed.markers;
    if events_path.is_file() {
        if let Ok((structured, structured_apis, structured_unsupported)) = parse_event_stream(&events_path) {
            if !structured.is_empty() {
                let from_trace: Vec<Value> = events
                    .iter()
                    .filter(|event| {
                        event
                            .get("api_name")
                            .and_then(|value| value.as_str())
                            .is_some_and(|name| structured_unsupported.contains_key(name))
                    })
                    .cloned()
                    .collect();
                events = structured;
                events.extend(from_trace);
                apis = structured_apis;
                unsupported = structured_unsupported;
            }
        }
    }
    let mut children = Vec::new();
    if depth < 2 {
        for child_path in child_candidates(&events).into_iter().take(3) {
            let Some(host) = guest_to_host(engine, &child_path) else { continue };
            if !host.is_file() {
                continue;
            }
            let child_raw = std::fs::read(&host).unwrap_or_default();
            let child_sha = hex::encode(Sha256::digest(&child_raw));
            if visited.contains(&child_sha) || machine_of(&child_raw).is_none() {
                continue;
            }
            let child_out = out.join(format!("child-{}", &child_sha[..12]));
            if let Ok(child_report) = run_one(
                &host,
                &child_out,
                engine,
                (seconds / 2).max(5),
                depth + 1,
                visited,
            ) {
                events.push(json!({
                    "event": "child_process",
                    "api_name": "sandbox.follow",
                    "args": [{"value": child_path, "display": child_path}],
                }));
                // run_one returns the summary; the child's full event list
                // lives in its report.json, and appending it is what makes the
                // parent's count match the Python worker.
                let child_report_path = child_report
                    .get("report")
                    .and_then(|value| value.as_str())
                    .map(PathBuf::from);
                if let Some(child_report_path) = child_report_path {
                    if let Ok(text) = std::fs::read_to_string(child_report_path) {
                        if let Ok(value) = serde_json::from_str::<Value>(&text) {
                            if let Some(child_events) = value
                                .get("runs")
                                .and_then(|value| value.as_array())
                                .and_then(|runs| runs.first())
                                .and_then(|run| run.get("events"))
                                .and_then(|value| value.as_array())
                            {
                                events.extend(child_events.iter().cloned());
                            }
                        }
                    }
                }
                children.push(json!({"path": child_path, "report": child_out}));
            }
        }
    }
    let report = json!({
        "runs": [{"events": events}],
        "mwemu": {
            "engine": engine.binary.display().to_string(),
            "machine": if machine == 0x8664 { "x86_64" } else { "x86" },
            "elapsed_seconds": (elapsed * 100.0).round() / 100.0,
            "timed_out": timed_out,
            "instruction_note": "see trace",
            "api_events": apis.values().sum::<usize>(),
            "unique_apis": apis.len(),
            "unsupported": unsupported,
            "markers": markers,
            "children": children,
        },
    });
    std::fs::write(out.join("report.json"), serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let events = report["runs"][0]["events"].as_array().cloned().unwrap_or_default();
    let (score, findings, decisive) = analyse(&events);
    let summary = json!({
        "sample": std::fs::canonicalize(sample).unwrap_or_else(|_| sample.to_path_buf()).display().to_string(),
        "sha256": sha,
        "score": score,
        "findings": findings,
        "decisive": decisive,
        "unpacked": [],
        "events": events.len(),
        "clock": {"virtual_ms": (elapsed * 1000.0) as u64, "skipped_sleeps": 0, "skipped_ms_total": 0},
        "report": out.join("report.json").display().to_string(),
        "mwemu": report["mwemu"],
    });
    std::fs::write(out.join("summary.json"), serde_json::to_string_pretty(&summary).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    Ok(summary)
}

fn machine_of(raw: &[u8]) -> Option<u16> {
    if raw.len() < 0x40 || &raw[0..2] != b"MZ" {
        return None;
    }
    let offset = u32::from_le_bytes(raw[0x3c..0x40].try_into().ok()?) as usize;
    if raw.len() < offset + 6 || &raw[offset..offset + 4] != b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(raw[offset + 4..offset + 6].try_into().ok()?))
}

struct Parsed {
    events: Vec<Value>,
    apis: BTreeMap<String, usize>,
    unsupported: BTreeMap<String, usize>,
    markers: Vec<String>,
}

fn parse_trace(path: &Path) -> Parsed {
    let mut parsed = Parsed { events: Vec::new(), apis: BTreeMap::new(), unsupported: BTreeMap::new(), markers: Vec::new() };
    let Ok(file) = std::fs::File::open(path) else { return parsed };
    let call = Regex::new(r"^\*\*\s+\d+>\s+\d+:[0-9a-fA-F]+\s+(?:([A-Za-z0-9_]+)!)?([A-Za-z_][A-Za-z0-9_]*)(.*)$").unwrap();
    let unsupported_re = Regex::new(r"unsupported\s+(\w+)!(\w+)\((.*)\)\s*$").unwrap();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if parsed.events.len() >= EVENT_LIMIT {
            break;
        }
        let lowered = line.to_ascii_lowercase();
        if let Some(captures) = unsupported_re.captures(&line) {
            let module = captures.get(1).map(|value| value.as_str()).unwrap_or("");
            let api = captures.get(2).map(|value| value.as_str()).unwrap_or("");
            let name = format!("{}.{}", module.to_ascii_lowercase(), api);
            *parsed.unsupported.entry(name.clone()).or_default() += 1;
            parsed.events.push(json!({
                "event": "api",
                "api_name": name,
                "args": arguments_of(captures.get(3).map(|value| value.as_str()).unwrap_or("")),
            }));
            continue;
        }
        if let Some(captures) = call.captures(&line) {
            let module = captures.get(1).map(|value| value.as_str()).unwrap_or("");
            let api = captures.get(2).map(|value| value.as_str()).unwrap_or("");
            let name = if module.is_empty() { api.to_string() } else { format!("{}.{}", module.to_ascii_lowercase(), api) };
            *parsed.apis.entry(name.clone()).or_default() += 1;
            parsed.events.push(json!({
                "event": "api",
                "api_name": name,
                "args": arguments_of(captures.get(3).map(|value| value.as_str()).unwrap_or("")),
            }));
            continue;
        }
        if lowered.contains("emulation failed") || lowered.contains("unhandled exception") {
            parsed.markers.push(line.chars().take(300).collect());
        }
    }
    parsed
}

fn parse_event_stream(path: &Path) -> Result<(Vec<Value>, BTreeMap<String, usize>, BTreeMap<String, usize>), String> {
    let file = std::fs::File::open(path).map_err(|error| error.to_string())?;
    let mut events = Vec::new();
    let mut apis = BTreeMap::new();
    let mut unsupported = BTreeMap::new();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if events.len() >= EVENT_LIMIT {
            break;
        }
        let Ok(record) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(name) = record.get("api").and_then(|value| value.as_str()) else { continue };
        let api_name = if let Some((module, api)) = name.split_once('!') {
            format!("{}.{}", module.to_ascii_lowercase(), api)
        } else {
            name.to_string()
        };
        let kind = record.get("kind").and_then(|value| value.as_str()).unwrap_or("api");
        if kind == "unsupported" {
            *unsupported.entry(api_name.clone()).or_default() += 1;
        } else {
            *apis.entry(api_name.clone()).or_default() += 1;
        }
        events.push(json!({
            "event": "api",
            "api_name": api_name,
            "args": arguments_of(record.get("arguments").and_then(|value| value.as_str()).unwrap_or("")),
        }));
    }
    Ok((events, apis, unsupported))
}

fn split_arguments(text: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut quoted = false;
    for character in text.chars() {
        if character == '"' {
            quoted = !quoted;
        } else if "([<{".contains(character) && !quoted {
            depth += 1;
        } else if ")]>}".contains(character) && !quoted {
            depth = (depth - 1).max(0);
        }
        if character == ',' && depth == 0 && !quoted {
            if !current.trim().is_empty() { pieces.push(current.trim().to_string()); }
            current.clear();
        } else {
            current.push(character);
        }
    }
    if !current.trim().is_empty() { pieces.push(current.trim().to_string()); }
    pieces
}

fn arguments_of(text: &str) -> Vec<Value> {
    split_arguments(text)
        .into_iter()
        .filter_map(|piece| {
            let value = piece.split_once('=').map(|(_, value)| value).unwrap_or(&piece).trim().trim_matches('"').to_string();
            (!value.is_empty()).then(|| json!({"value": value, "display": value}))
        })
        .collect()
}

fn guest_to_host(engine: &Engine, guest: &str) -> Option<PathBuf> {
    let mut text = guest.trim().trim_matches('"').replace('/', "\\");
    for prefix in ["\\\\?\\", "\\??\\"] {
        if let Some(rest) = text.strip_prefix(prefix) { text = rest.to_string(); }
    }
    if text.len() >= 2 && text.as_bytes()[1] == b':' { text = text[2..].to_string(); }
    let text = text.trim_start_matches('\\');
    let parts: Vec<&str> = text.split('\\').filter(|part| !part.is_empty() && *part != ".").collect();
    if parts.iter().any(|part| *part == "..") { return None; }
    let mut path = engine.file_root();
    for part in parts { path.push(part); }
    Some(path)
}

fn child_candidates(events: &[Value]) -> Vec<String> {
    let pattern = Regex::new(r#"(?i)(?:[a-z]:\\[^"\s]+?\.exe|[^"\s]+?\.exe)"#).unwrap();
    let mut seen: Vec<String> = Vec::new();
    for event in events {
        let name = event.get("api_name").and_then(|value| value.as_str()).unwrap_or("").to_ascii_lowercase();
        if !["createprocess", "shellexecute", "winexec", "createuserprocess"].iter().any(|word| name.contains(word)) {
            continue;
        }
        for argument in event.get("args").and_then(|value| value.as_array()).into_iter().flatten() {
            let text = argument.get("value").and_then(|value| value.as_str()).unwrap_or("");
            for found in pattern.find_iter(text) {
                let value = found.as_str().to_string();
                if !seen.contains(&value) { seen.push(value); }
            }
        }
    }
    seen
}

fn analyse(events: &[Value]) -> (f64, Vec<Value>, Vec<String>) {
    const FAMILIES: &[(&str, &[&str])] = &[
        ("environment_probe", &["getsystemmetrics", "gettickcount", "queryperformancecounter", "globalmemorystatus", "getcomputername", "getusername", "getversionex", "getsysteminfo", "getvolumeinformation", "getadaptersinfo", "getlocaltime", "gettimezoneinformation", "systemtimeasfiletime"]),
        ("anti_analysis", &["isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstring", "findwindow", "getforegroundwindow", "enumwindows", "setunhandledexceptionfilter", "queryperformancefrequency"]),
        ("process_enum", &["createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses", "enumprocessmodules", "getprocessimagefilename"]),
        ("injection", &["virtualallocex", "writeprocessmemory", "createremotethread", "ntmapviewofsection", "setthreadcontext", "queueuserapc", "ntunmapviewofsection", "virtualprotectex"]),
        ("persistence", &["regsetvalue", "regcreatekey", "createservice", "openscmanager", "schtasks", "createscheduledtask", "writefile"]),
        ("process_creation", &["createprocess", "shellexecute", "winexec"]),
        ("driver_load", &["ntloaddriver", "loaddriver"]),
        ("raw_disk", &["physicaldrive", "harddisk0"]),
        ("download", &["internetopen", "internetsetoption", "httpsendrequest", "urldownloadtofile", "winhttpopen", "winhttpsendrequest", "wsastartup", "wsaconnect", "socket", "connect", "send", "recv", "getaddrinfo", "dnsquery"]),
        ("defence_tampering", &["setmppreference", "disablerealtime", "vssadmin", "delete shadows", "bcdedit", "recoveryenabled", "wevtutil", "cleareventlog"]),
        ("process_termination", &["terminateprocess", "ntterminateprocess", "deletefile", "regdeletekey", "regdeletevalue"]),
        ("credential_access", &["lsass", "mimikatz", "credread", "credential", "cryptunprotectdata"]),
        ("file_write", &["createfile", "writefile", "copyfile", "movefile", "setfileattributes"]),
    ];
    const SEVERITY: &[(&str, f64)] = &[
        ("injection", 0.9), ("defence_tampering", 0.85), ("credential_access", 0.9),
        ("raw_disk", 0.9), ("driver_load", 0.7), ("dropper_launch", 0.8),
        ("download", 0.6), ("persistence", 0.6), ("process_creation", 0.5),
        ("environment_probe", 0.25), ("anti_analysis", 0.4), ("process_enum", 0.3),
        ("file_write", 0.2), ("process_termination", 0.15),
    ];
    let severity: HashMap<&str, f64> = SEVERITY.iter().copied().collect();
    let mut seen: BTreeMap<&str, (usize, BTreeSet<String>)> = BTreeMap::new();
    for event in events {
        let Some(name) = event.get("api_name").and_then(|value| value.as_str()) else { continue };
        let name = name.to_ascii_lowercase().replace('!', ".");
        let short = name.rsplit('.').next().unwrap_or(&name);
        for (family, needles) in FAMILIES {
            if needles.iter().any(|needle| short.contains(needle) || name.contains(needle)) {
                let entry = seen.entry(*family).or_default();
                entry.0 += 1;
                if entry.1.len() < 5 { entry.1.insert(name.clone()); }
            }
        }
    }
    let mut written = BTreeSet::new();
    let mut started = BTreeSet::new();
    let path_re = Regex::new(r#"(?i)(?:[a-z]:\\[^"\\\s,]+?|[^"\\\s,]+?)\.(?:exe|dll)"#).unwrap();
    for event in events {
        let name = event.get("api_name").and_then(|value| value.as_str()).unwrap_or("").to_ascii_lowercase();
        let text = argument_text(event);
        let paths: BTreeSet<String> = path_re.find_iter(&text).map(|found| {
            found.as_str().replace('/', "\\").rsplit('\\').next().unwrap_or("").to_ascii_lowercase()
        }).collect();
        if ["writefile", "createfile", "copyfile", "movefile", "setfileattributes"].iter().any(|word| name.contains(word)) {
            written.extend(paths.iter().cloned());
        }
        if ["createprocess", "shellexecute", "winexec", "child_process"].iter().any(|word| name.contains(word)) {
            started.extend(paths.iter().cloned());
        }
    }
    let launched: Vec<String> = written.intersection(&started).cloned().collect();
    if !launched.is_empty() {
        let examples: BTreeSet<String> = launched.iter().cloned().take(5).collect();
        seen.insert("dropper_launch", (launched.len(), examples));
    }
    let mut findings = Vec::new();
    let mut score: f64 = 0.0;
    for (family, (calls, examples)) in &seen {
        let weight = *severity.get(family).unwrap_or(&0.1);
        score = score.max(weight);
        findings.push(json!({
            "family": family,
            "severity": weight,
            "calls": calls,
            "examples": examples,
            "description": format!("{family}: {calls} call(s), e.g. {}", examples.iter().cloned().collect::<Vec<_>>().join(", ")),
        }));
    }
    if findings.len() >= 3 { score = (score + 0.1).min(1.0); }
    let decisive = decisive_behaviours(events, &written, &started);
    ((score * 1000.0).round() / 1000.0, findings, decisive)
}

fn argument_text(event: &Value) -> String {
    let mut parts = Vec::new();
    for argument in event.get("args").and_then(|value| value.as_array()).into_iter().flatten() {
        for key in ["display", "value"] {
            if let Some(value) = argument.get(key).and_then(|value| value.as_str()) {
                parts.push(value.to_ascii_lowercase());
            }
        }
    }
    parts.join(" ")
}

fn decisive_behaviours(events: &[Value], written: &BTreeSet<String>, started: &BTreeSet<String>) -> Vec<String> {
    let mut hits = Vec::new();
    for event in events {
        let api = event.get("api_name").and_then(|value| value.as_str()).unwrap_or("").to_ascii_lowercase();
        let both = format!("{} {}", api, argument_text(event));
        for (needle, label) in [
            ("vssadmin", "ransomware-shape"), ("delete shadows", "ransomware-shape"), ("wbadmin", "ransomware-shape"), ("bcdedit", "ransomware-shape"),
            ("lsass", "credential-tool"), ("mimikatz", "credential-tool"), ("sekurlsa", "credential-tool"), ("credential", "credential-tool"),
            ("wevtutil", "event-log-clear"), ("cleareventlog", "event-log-clear"), ("clear-eventlog", "event-log-clear"),
            ("physicaldrive", "bootkit-disk-write"), ("harddisk0", "bootkit-disk-write"),
        ] {
            if both.contains(needle) { push_unique(&mut hits, label); }
        }
        if both.contains(".sys") && ["createservice", "startservice", "ntloaddriver"].iter().any(|word| both.contains(word)) {
            push_unique(&mut hits, "byovd-driver");
        }
        if api.contains("ntloaddriver") { push_unique(&mut hits, "driver-load"); }
    }
    if written.intersection(started).next().is_some() { push_unique(&mut hits, "dropper-launch"); }
    hits
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|held| held == value) { values.push(value.to_owned()); }
}


