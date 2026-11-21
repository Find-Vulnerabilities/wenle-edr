//! The sandbox's cached opinion, read where every scan can see it.
//!
//! # Why this is a cache and not a call
//!
//! Emulating a sample in Speakeasy takes tens of seconds and cannot happen on
//! the path that decides whether an open is allowed: the driver waits 250 ms.
//! So the split is by file, not by process:
//!
//! * a scan that lands in the suspicious band and finds no cached answer writes
//!   a small job file into `sandbox\queue\`, and returns its ordinary verdict
//!   at once;
//! * a worker outside the service picks the job up, runs the sample under the
//!   virtual clock, and leaves `sandbox\results\<sha256>.json`;
//! * the next scan of the same bytes reads that file and adds a detection.
//!
//! The detection is added *after* `Assessment::finalize`, so it is visible in
//! the report and in the event stream but does not move the verdict. That is
//! deliberate for the first release: a sandbox run is corroborating evidence,
//! and a model that has not been measured on real machines should not convict
//! on its own.
//!
//! # Where the directories are
//!
//! `WENLE_SANDBOX_DIR` when set (tests and portable installs), otherwise
//! `%ProgramData%\WenleAV\sandbox`. The worker writes the same layout.

use std::path::{Path, PathBuf};

use av_core::{Assessment, Detection, DetectionSource, Severity};

/// The sandbox's state directory.
pub fn root() -> PathBuf {
    if let Some(directory) = std::env::var_os("WENLE_SANDBOX_DIR") {
        return PathBuf::from(directory);
    }
    PathBuf::from(r"C:\ProgramData\WenleAV\sandbox")
}

fn is_portable_executable(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "exe" | "dll" | "sys" | "scr" | "cpl" | "ocx" | "efi" | "com"
    )
}

/// Read the sandbox's cached answer, or queue the file for one.
///
/// Called once per scan with the file's SHA-256. Returns true when a cached
/// answer was found, whether or not it produced a detection, so a caller can
/// tell "the sandbox has looked" from "it has not".
pub fn consult(
    path: &Path,
    sha256: Option<&str>,
    assessment: &mut Assessment,
) -> bool {
    let Some(sha256) = sha256 else {
        return false;
    };
    if !is_portable_executable(path) {
        return false;
    }
    let root = root();
    let result = root.join("results").join(format!("{sha256}.json"));
    if let Ok(text) = std::fs::read_to_string(&result) {
        report(&text, assessment);
        return true;
    }

    // No answer yet. Ask for one, once per file.
    let queue = root.join("queue");
    let _ = std::fs::create_dir_all(&queue);
    let job = queue.join(format!("{sha256}.job"));
    if !job.exists() {
        let body = format!("{}\n{}\n", path.display(), sha256);
        if std::fs::write(&job, body).is_ok() {
            log::debug!("sandbox: queued {} for a run", path.display());
        }
    }
    false
}

/// Turn one `summary.json` into a detection.
fn report(text: &str, assessment: &mut Assessment) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return;
    };
    let score = value
        .get("score")
        .and_then(|value| value.as_f64())
        .unwrap_or(0.0) as f32;
    let families: Vec<String> = value
        .get("findings")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("family")
                        .and_then(|family| family.as_str())
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();
    if score <= 0.0 && families.is_empty() {
        return;
    }
    let unpacked = value
        .get("unpacked")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    item.get("verdict")
                        .and_then(|verdict| verdict.as_str())
                        == Some("malicious")
                })
                .count()
        })
        .unwrap_or(0usize);
    let severity = if score >= 0.8 {
        Severity::Medium
    } else {
        Severity::Low
    };
    assessment.push(Detection::new(
        "sandbox/behaviour",
        format!(
            "The sandbox ran this sample under a virtual clock: behaviour score {score:.2} of 1, \
             families: {}. {} unpacked region(s) were convicted by this product's own engine. \
             Reported, not convicted: the sandbox is corroborating evidence.",
            if families.is_empty() {
                "none".to_string()
            } else {
                families.join(", ")
            },
            unpacked
        ),
        severity,
        DetectionSource::Heuristic,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// The two tests share one process environment; without this lock one
    /// removes the variable while the other is reading it.
    static ENVIRONMENT: Mutex<()> = Mutex::new(());

    fn scratch() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "wenle-sandbox-test-{}",
            std::process::id() as u64 + std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.subsec_nanos() as u64)
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn a_suspicious_pe_without_an_answer_is_queued_once() {
        let _guard = ENVIRONMENT.lock().unwrap();
        let directory = scratch();
        std::env::set_var("WENLE_SANDBOX_DIR", &directory);
        let mut assessment = Assessment::default();
        let found = consult(
            Path::new(r"C:\Users\wensz\sample.exe"),
            Some("abc123"),
            &mut assessment,
        );
        assert!(!found);
        let job = directory.join("queue").join("abc123.job");
        assert!(job.exists());
        // A second look does not write a second job.
        let modified = std::fs::metadata(&job).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        consult(
            Path::new(r"C:\Users\wensz\sample.exe"),
            Some("abc123"),
            &mut assessment,
        );
        assert_eq!(std::fs::metadata(&job).unwrap().modified().unwrap(), modified);
        std::env::remove_var("WENLE_SANDBOX_DIR");
    }

    #[test]
    fn a_cached_answer_becomes_a_detection_that_does_not_convict() {
        let _guard = ENVIRONMENT.lock().unwrap();
        let directory = scratch();
        std::env::set_var("WENLE_SANDBOX_DIR", &directory);
        std::fs::create_dir_all(directory.join("results")).unwrap();
        std::fs::write(
            directory.join("results").join("abc123.json"),
            r#"{"score": 0.9, "findings": [{"family": "injection"}], "unpacked": [{"verdict": "malicious"}]}"#,
        )
        .unwrap();
        let mut assessment = Assessment::default();
        let found = consult(
            Path::new(r"C:\Users\wensz\sample.exe"),
            Some("abc123"),
            &mut assessment,
        );
        assert!(found);
        assert!(assessment
            .detections
            .iter()
            .any(|detection| detection.rule_id == "sandbox/behaviour"));
        std::env::remove_var("WENLE_SANDBOX_DIR");
    }
}
