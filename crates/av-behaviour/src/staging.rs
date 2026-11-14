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
    /// When a Run key was written, and when a task or service install command
    /// was seen. Persistence is one act in two halves.
    run_key_at: Option<u64>,
    task_at: Option<u64>,
    /// When a recovery-destroying command line was seen.
    shadow_at: Option<u64>,
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
                        self.task_at = Some(record.timestamp);
                        if let Some(when) = self.run_key_at {
                            if record.timestamp.saturating_sub(when) <= 120 * crate::TICKS_PER_SECOND {
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
                        self.shadow_at = Some(record.timestamp);
                        let recent_renames = self
                            .renames
                            .values()
                            .any(|queue| queue.len() >= 20);
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
                        self.run_key_at = Some(record.timestamp);
                        // Persistence is two halves: the key is written and
                        // something is arranged to act on it. One half alone is
                        // what every installer does.
                        if let Some(when) = self.task_at {
                            if record.timestamp.saturating_sub(when) <= 120 * crate::TICKS_PER_SECOND {
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
            11,
            10,
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
            11,
            10,
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
}
