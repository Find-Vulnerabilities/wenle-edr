//! A file of behaviour events, for training a sequence model on this machine.
//!
//! # Why a file and not a service feature
//!
//! The model has to learn what ordinary work looks like *on this machine*: a
//! compiler's file burst and a browser's temp churn are nothing like each other,
//! and neither is inferred from a paper. Collecting that takes days, and the
//! collection has to be inspectable, bounded, and off by default.
//!
//! One line per event, oldest first, one space between fields:
//!
//! ```text
//! <pid> <ppid> <timestamp-micros> <f0> <f1> ... <f32>
//! ```
//!
//! The floats are [`av_behaviour::Features`], so the trainer reads exactly the
//! numbers the service will serve, computed by the same code. A trainer that
//! re-derived the features could disagree with the service about what a path is,
//! and the disagreement would look like a model that works in Python and fails
//! on the machine.
//!
//! # Why a rotation and not a size check
//!
//! A behaviour log is written by the service on the path it protects, and a
//! service that filled a disk would be the outage it exists to prevent. The file
//! is renamed to `.1` at the cap and a new one is started; the caller decides
//! whether a second file is worth keeping.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use av_behaviour::{Features, Record};

/// The default cap: enough for a day of ordinary use, small enough that a
/// forgotten switch is not an incident.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// The collector, or nothing.
///
/// `None` is the off state rather than a bool beside a file handle, so that a
/// service compiled without collection costs one branch instead of a field that
/// is sometimes empty.
#[derive(Debug)]
pub struct BehaviourLog {
    path: PathBuf,
    file: File,
    max_bytes: u64,
    written: u64,
}

impl BehaviourLog {
    /// Open the log for appending, creating it if it is not there.
    ///
    /// A failure to open is not an error for the caller: collection is a
    /// diagnostic and a service that refused to start because it could not write
    /// a diagnostic would be trading a working product for a log.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|meta| meta.len()).unwrap_or(0);
        Ok(Self {
            path,
            file,
            max_bytes: max_bytes.max(1),
            written,
        })
    }

    /// One line for one event.
    pub fn record(&mut self, record: &Record, features: &Features) {
        let line = line(record, features);
        // A failed write is not fatal: the service's job is the machine in front
        // of it, and this file is evidence about it that can be lost.
        if self.file.write_all(line.as_bytes()).is_err() {
            return;
        }
        self.written += line.len() as u64;
        if self.written >= self.max_bytes {
            self.rotate();
        }
    }

    /// Start a new file, keeping one previous generation.
    fn rotate(&mut self) {
        let previous = self.path.with_extension("1");
        // The rename is allowed to fail: if the file cannot be moved the log
        // simply keeps growing, which is worse than a rotation and better than
        // losing the events.
        let _ = std::fs::rename(&self.path, &previous);
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            self.file = file;
            self.written = 0;
        }
    }

    /// Where the file is.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Microseconds since the Unix epoch.
fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as u64)
        .unwrap_or(0)
}

/// The line for one event.
///
/// `pid` and `ppid` are what the trainer groups by; the timestamp orders the
/// story within a process and lets the trainer cut a window when the process
/// went quiet. Numbers are written with three decimals -- enough to keep a class
/// flag exact and a time gap distinguishable, short enough that a day of events
/// is a file a person can open.
pub fn line(record: &Record, features: &Features) -> String {
    let mut out = String::with_capacity(8 + 8 + 20 + av_behaviour::WIDTH * 6);
    out.push_str(&record.process_id.to_string());
    out.push(' ');
    out.push_str(&record.parent_process_id.to_string());
    out.push(' ');
    // Wall-clock, not the driver's timestamp. The driver counts in its own
    // units from its own start, and a label file written by a person is in Unix
    // microseconds; measured on 2026-11-14, the two never met and every
    // malicious window held zero events. The gap between events is already one
    // of the features, so the driver's clock loses nothing by being dropped
    // here.
    out.push_str(&now_micros().to_string());
    for value in features.0.iter() {
        out.push(' ');
        out.push_str(&format!("{value:.3}"));
    }
    out.push('\n');
    out
}

/// The collector, when the environment asked for one.
///
/// `WENLE_BEHAVIOUR_LOG` names the file and `WENLE_BEHAVIOUR_LOG_MAX` the cap in
/// bytes. The environment rather than the configuration on purpose: this is a
/// diagnostic a person turns on for a day of their own work, and a setting in
/// the product's configuration would be a setting an attacker could read to
/// know what is being recorded -- or turn off. A path that cannot be opened
/// turns collection off and says so, because a service that refused to start
/// over a diagnostic would be the outage.
pub fn from_environment() -> Option<BehaviourLog> {
    let path = std::env::var_os("WENLE_BEHAVIOUR_LOG")?;
    let max_bytes = std::env::var("WENLE_BEHAVIOUR_LOG_MAX")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_BYTES);
    match BehaviourLog::open(PathBuf::from(path), max_bytes) {
        Ok(log) => {
            log::info!(
                "behaviour events are being written to {}",
                log.path().display()
            );
            Some(log)
        }
        Err(error) => {
            log::warn!("behaviour collection was asked for and could not start: {error}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use av_behaviour::{Action, Subject};

    fn record() -> Record {
        Record {
            timestamp: 1_700_000_000_000_000,
            subject: Subject::File,
            action: Action::FileWritten,
            detail: 0,
            path: Some(r"C:\Users\x\AppData\Local\Temp\a.ps1".to_string()),
            folded_path: None,
            value: None,
            folded_value: None,
            command_line: None,
            process_id: 42,
            parent_process_id: 7,
        }
    }

    #[test]
    fn a_line_carries_the_identity_and_the_width_of_features() {
        let record = record();
        let features = Features::of(&record, 0);
        let line = line(&record, &features);
        let fields: Vec<&str> = line.trim_end().split(' ').collect();
        assert_eq!(fields[0], "42");
        assert_eq!(fields[1], "7");
        assert_eq!(fields[2], "1700000000000000");
        assert_eq!(fields.len(), 3 + av_behaviour::WIDTH);
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn the_log_appends_and_rotates_at_the_cap() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("behaviour.log");
        let record = record();
        let features = Features::of(&record, 0);
        let mut log = BehaviourLog::open(&path, 200).expect("the log opens");
        for _ in 0..40 {
            log.record(&record, &features);
        }
        drop(log);
        assert!(path.exists());
        assert!(path.with_extension("1").exists(), "one previous generation");
    }
}
