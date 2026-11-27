//! Canary files for ransomware, and the alert they raise when touched.
//!
//! A canary is a small hidden file in a folder ransomware likes to encrypt:
//! Documents, Desktop, Pictures and Downloads of every profile on the machine.
//! Nothing in the product reads it, executes it or depends on it; its only job
//! is to be a file whose modification is never legitimate. A process that
//! rewrites it is doing to this machine what ransomware does, and the product
//! can say so without waiting to recognise the encryptor.
//!
//! This is detection, not prevention. The driver's write path is not on the
//! canary, and the service does not roll anything back — the user asked for the
//! decoy and for nothing beyond it. What the user gets is a line in
//! `alerts.jsonl`, which `wenle-notify` turns into a toast, and a log entry.
//!
//! The check is a hash-free byte comparison once every two seconds. A canary is
//! a few dozen bytes and there are four per profile, so the cost is four small
//! reads per profile per two seconds; the alternative, a filesystem watch per
//! canary, is more handles for less certainty because a delete and a rename
//! arrive as different events.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How often the canaries are read.
const CHECK: Duration = Duration::from_secs(2);

/// The alert file the notifier polls. One line of JSON per event.
pub const ALERTS_FILE: &str = "alerts.jsonl";

/// Start the canary thread.
///
/// Called once from `Host::open`, after the data directory exists. The thread
/// is deliberately detached: it holds no state the host needs to stop, and a
/// service shutdown is a process exit.
pub fn start(data_dir: PathBuf) {
    let _ = std::thread::Builder::new()
        .name("wenle-canary".to_owned())
        .spawn(move || run(data_dir));
}

fn run(data_dir: PathBuf) {
    let canaries = install();
    if canaries.is_empty() {
        log::debug!("ransomware canaries: no profile folders to place them in");
        return;
    }
    log::info!(
        "ransomware canaries: {} file(s) placed in user folders",
        canaries.len()
    );
    let mut last_alert: HashMap<PathBuf, std::time::Instant> = HashMap::new();
    loop {
        std::thread::sleep(CHECK);
        for (path, expected) in &canaries {
            let state = match std::fs::read(path) {
                Ok(bytes) if bytes == *expected => continue,
                Ok(_) => "rewritten",
                Err(_) => "missing",
            };
            // One alert per canary per minute. Ransomware rewriting the same
            // file every two seconds would otherwise turn the alert file into a
            // log that grows without bound at exactly the moment disk space
            // matters.
            let now = std::time::Instant::now();
            let quiet = last_alert
                .get(path)
                .is_some_and(|last| now.duration_since(*last) < Duration::from_secs(60));
            if quiet {
                continue;
            }
            last_alert.insert(path.clone(), now);
            log::warn!(
                "ransomware canary {} was {state}: {}",
                path.display(),
                "a file that nothing in this product writes was changed"
            );
            append_alert(&data_dir, path, state);
            // Put it back, so the next touch is visible again. If writing fails
            // the alert has already been raised and the loop continues.
            let _ = std::fs::write(path, expected);
            let _ = hide(path);
        }
    }
}

/// Place the canaries and return what each one should contain.
fn install() -> HashMap<PathBuf, Vec<u8>> {
    let mut placed = HashMap::new();
    for profile in profiles() {
        for folder in ["Desktop", "Documents", "Pictures", "Downloads"] {
            let directory = profile.join(folder);
            if !directory.is_dir() {
                continue;
            }
            // A restart writes a fresh name; without this the previous run's
            // canaries stay in the folder forever, hidden, unmonitored and
            // indistinguishable from an attacker's leftovers.
            if let Ok(entries) = std::fs::read_dir(&directory) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with("~wenle-canary-") {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
            let name = format!(
                "~wenle-canary-{:x}-{:x}.txt",
                std::process::id(),
                stamp()
            );
            let path = directory.join(name);
            let content = format!("WENLE-CANARY {:x} {:x}\r\nDo not take this file.\r\n", stamp(), std::process::id())
                .into_bytes();
            if std::fs::write(&path, &content).is_ok() && hide(&path) {
                placed.insert(path, content);
            }
        }
    }
    placed
}

/// The real profiles on this machine.
///
/// The service runs as SYSTEM, so `USERPROFILE` is the service profile and every
/// path derived from it would place canaries where no user would ever see them.
/// The profile directories are therefore enumerated from `C:\Users`, skipping
/// the three names Windows creates that are not a person.
fn profiles() -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    let Ok(entries) = std::fs::read_dir(r"C:\Users") else {
        return profiles;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.eq_ignore_ascii_case("Public")
            || name.eq_ignore_ascii_case("Default")
            || name.eq_ignore_ascii_case("Default User")
            || name.eq_ignore_ascii_case("All Users")
        {
            continue;
        }
        if entry.path().is_dir() {
            profiles.push(entry.path());
        }
    }
    profiles
}

/// A number that changes between restarts, so a stale canary and a fresh one
/// are not confused by their names alone.
fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}

#[cfg(windows)]
fn hide(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_NORMAL,
    };

    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    // SAFETY: the pointer is to a NUL-terminated buffer that lives for the call.
    unsafe {
        SetFileAttributesW(
            PCWSTR(wide.as_ptr()),
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_NORMAL,
        )
        .is_ok()
    }
}

#[cfg(not(windows))]
fn hide(_path: &Path) -> bool {
    true
}

/// Append one alert line for the notifier. Failures are logged and swallowed:
/// a full disk must not end the canary thread.
fn append_alert(data_dir: &Path, path: &Path, state: &str) {
    let line = serde_json::json!({
        "when": chrono::Utc::now().to_rfc3339(),
        "kind": "ransomware-canary",
        "path": path.display().to_string(),
        "detail": state,
    });
    let file = data_dir.join(ALERTS_FILE);
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .and_then(|mut file| {
            writeln!(file, "{line}")?;
            file.sync_data()
        });
    if let Err(error) = result {
        log::warn!("the ransomware alert could not be written to {}: {error}", file.display());
    }
}
