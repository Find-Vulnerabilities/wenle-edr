//! Autostart rollback guard.
//!
//! The behaviour engine sees a persistence write and stops the process, but the
//! value has already been written by then. This module keeps a baseline of the
//! places a program can arrange to start again and puts the baseline back when
//! one of them changes:
//!
//! * registry keys exported with `reg.exe` (Run, RunOnce, policy Run, Winlogon,
//!   Session Manager, AppInit, IFEO, Active Setup, and every loaded user's Run
//!   keys);
//! * files in the user and common Startup folders;
//! * task files under `System32\Tasks`;
//! * service names in the SCM.
//!
//! It is deliberately a user-mode polling guard. It is not a security boundary
//! against an administrator, and it does not claim to be the driver's registry
//! callback: it is the cheap second layer that makes the difference between a
//! report and a machine that is actually still clean after the process stops.
//!
//! Baseline and temporary files live under
//! `%ProgramData%\WenleAV\persistence-guard`, not in the product directory, so
//! they are not part of the integrity manifest.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(1500);

/// Where the guard keeps its baselines.
fn state_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("WenleAV").join("persistence-guard")
}

fn temp_dir() -> PathBuf {
    std::env::temp_dir().join("wenle-persistence-guard")
}

fn system32(exe: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(exe)
}

fn run(exe: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new(exe).args(args).output().ok()?;
    Some(output.stdout)
}

fn file_stem(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn export(key: &str, path: &Path) -> Vec<u8> {
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    let _ = std::fs::remove_file(path);
    let reg = system32("reg.exe");
    let _ = run(
        &reg,
        &["export", key, path.to_string_lossy().as_ref(), "/y"],
    );
    std::fs::read(path).unwrap_or_default()
}

fn import(key: &str, path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let reg = system32("reg.exe");
    Command::new(reg)
        .args(["import", path.to_string_lossy().as_ref()])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn user_sids() -> Vec<String> {
    let Some(text) = run(&system32("reg.exe"), &["query", "HKU"]) else {
        return Vec::new();
    };
    String::from_utf8_lossy(&text)
        .lines()
        .filter_map(|line| {
            let key = line.trim().strip_prefix("HKEY_USERS\\")?;
            (key.starts_with("S-1-5-21-") && !key.contains('\\')).then(|| key.to_string())
        })
        .collect()
}

fn registry_targets() -> Vec<String> {
    let mut keys = vec![
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce".to_string(),
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run".to_string(),
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".to_string(),
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager".to_string(),
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows".to_string(),
        r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options".to_string(),
        r"HKLM\Software\Microsoft\Active Setup\Installed Components".to_string(),
    ];
    for sid in user_sids() {
        let prefix = format!(r"HKEY_USERS\{sid}\Software\Microsoft\Windows\CurrentVersion");
        keys.push(format!(r"{prefix}\Run"));
        keys.push(format!(r"{prefix}\RunOnce"));
        keys.push(format!(r"{prefix}\Policies\Explorer\Run"));
    }
    keys
}

fn baseline_registry(dir: &Path) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for key in registry_targets() {
        let path = dir.join(format!("{}.reg", file_stem(&key)));
        let _ = export(&key, &path);
        keys.insert(key);
    }
    keys
}

fn exported_sections(path: &Path) -> BTreeSet<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return BTreeSet::new();
    };
    // `reg export` writes UTF-16LE with a BOM. `read_to_string` rejects it,
    // which made every new IFEO/Active Setup subkey invisible to the guard.
    let text = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&bytes).into_owned()
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let section = line.strip_prefix('[')?.strip_suffix(']')?;
            Some(section.replace(r"HKEY_LOCAL_MACHINE\", r"HKLM\"))
        })
        .collect()
}

fn remove_new_subkeys(key: &str, baseline: &Path, current: &Path) {
    let before = exported_sections(baseline);
    if before.is_empty() {
        return;
    }
    let reg = system32("reg.exe");
    for section in exported_sections(current) {
        if section != key && !before.contains(&section) {
            let _ = Command::new(&reg).args(["delete", &section, "/f"]).output();
            log::warn!("persistence guard: removed new autostart subkey {section}");
        }
    }
}

fn audit_registry(dir: &Path, keys: &BTreeSet<String>) {
    let temp = temp_dir();
    let _ = std::fs::create_dir_all(&temp);
    for key in keys {
        let baseline = dir.join(format!("{}.reg", file_stem(key)));
        let current = temp.join(format!("{}.reg", file_stem(key)));
        let now = export(key, &current);
        let before = std::fs::read(&baseline).unwrap_or_default();
        if now != before {
            let lower = key.to_ascii_lowercase();
            // `reg import` merges: it restores values the baseline had but
            // leaves values the attacker added. A Run key has no subtree
            // state worth preserving beyond its own values, so delete it
            // first and import the baseline into the empty key.
            let subkey_only = lower.contains(r"\active setup\installed components")
                || lower.contains(r"\image file execution options");
            if subkey_only {
                remove_new_subkeys(key, &baseline, &current);
                let _ = std::fs::remove_file(&current);
                continue;
            }
            let replace_whole_key = lower.contains(r"\currentversion\run")
                || lower.contains(r"\policies\explorer\run");
            if replace_whole_key {
                let reg = system32("reg.exe");
                let _ = Command::new(reg).args(["delete", key, "/f"]).output();
            }
            if import(key, &baseline) {
                log::warn!("persistence guard: restored changed autostart key {key}");
            } else {
                // Winlogon is held open by the interactive session and
                // `reg import` cannot replace its whole subtree while it is
                // in use. Restore the two values that actually start a
                // program, with value-level writes that do not need to
                // replace the key.
                let lower = key.to_ascii_lowercase();
                let reg = system32("reg.exe");
                let restored = if lower.ends_with(r"\winlogon") {
                    let shell = Command::new(&reg)
                        .args([
                            "add",
                            key,
                            "/v",
                            "Shell",
                            "/t",
                            "REG_SZ",
                            "/d",
                            "explorer.exe",
                            "/f",
                        ])
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false);
                    let userinit = Command::new(&reg)
                        .args([
                            "add",
                            key,
                            "/v",
                            "Userinit",
                            "/t",
                            "REG_SZ",
                            "/d",
                            r"C:\Windows\system32\userinit.exe,",
                            "/f",
                        ])
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false);
                    shell && userinit
                } else if lower.ends_with(r"\session manager") {
                    Command::new(&reg)
                        .args([
                            "add",
                            key,
                            "/v",
                            "BootExecute",
                            "/t",
                            "REG_MULTI_SZ",
                            "/d",
                            "autocheck autochk *",
                            "/f",
                        ])
                        .output()
                        .map(|output| output.status.success())
                        .unwrap_or(false)
                } else {
                    false
                };
                if restored {
                    log::warn!("persistence guard: restored changed autostart values in {key}");
                } else {
                    log::error!("persistence guard: could not restore autostart key {key}");
                }
            }
        }
        let _ = std::fs::remove_file(current);
    }
}

fn startup_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    )];
    if let Ok(entries) = std::fs::read_dir(r"C:\Users") {
        for entry in entries.flatten() {
            dirs.push(
                entry
                    .path()
                    .join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
            );
        }
    }
    dirs
}

fn files_under(dir: &Path) -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            out.insert(path);
        }
    }
    out
}

fn baseline_files(dir: &Path, sub: &str) -> BTreeSet<PathBuf> {
    let root = dir.join(sub);
    let _ = std::fs::create_dir_all(&root);
    let mut out = BTreeSet::new();
    for dir in startup_dirs() {
        for path in files_under(&dir) {
            out.insert(path);
        }
    }
    out
}

fn audit_files(dir: &Path, baseline: &BTreeSet<PathBuf>, kind: &str) {
    for dir in startup_dirs() {
        for path in files_under(&dir) {
            if !baseline.contains(&path) {
                if std::fs::remove_file(&path).is_ok() {
                    log::warn!("persistence guard: removed new {kind} {}", path.display());
                }
            }
        }
    }
}

fn task_files() -> BTreeSet<PathBuf> {
    let root = PathBuf::from(r"C:\Windows\System32\Tasks");
    let mut out = BTreeSet::new();
    fn walk(root: &Path, dir: &Path, out: &mut BTreeSet<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else if path.is_file() {
                out.insert(path.strip_prefix(root).unwrap_or(&path).to_path_buf());
            }
        }
    }
    walk(&root, &root, &mut out);
    out
}

fn delete_task(relative: &Path) {
    let name = relative.to_string_lossy().replace('/', r"\");
    let schtasks = system32("schtasks.exe");
    let _ = Command::new(schtasks)
        .args(["/Delete", "/TN", &name, "/F"])
        .output();
}

fn service_names() -> BTreeSet<String> {
    let sc = system32("sc.exe");
    let Some(out) = run(&sc, &["query", "state=", "all"]) else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&out)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("SERVICE_NAME:")
                .map(|name| name.trim().to_string())
        })
        .collect()
}

fn delete_service(name: &str) {
    let sc = system32("sc.exe");
    let _ = Command::new(sc).args(["delete", name]).output();
}

/// Start the guard and return its thread.
///
/// Called once from the service and from `--console`. The thread has no stop
/// flag: it is a service-lifetime thread and the process ending is the stop.
pub fn start() -> thread::JoinHandle<()> {
    thread::spawn(|| {
        let dir = state_dir();
        let _ = std::fs::create_dir_all(&dir);
        let temp = temp_dir();
        let _ = std::fs::create_dir_all(&temp);
        let keys = baseline_registry(&dir);
        let startup = baseline_files(&dir, "startup");
        let tasks = task_files();
        let services = service_names();
        log::info!(
            "persistence guard: baseline {} registry keys, {} startup files, {} tasks, {} services",
            keys.len(),
            startup.len(),
            tasks.len(),
            services.len()
        );
        loop {
            thread::sleep(TICK);
            audit_registry(&dir, &keys);
            audit_files(&dir, &startup, "startup item");
            for relative in task_files() {
                if !tasks.contains(&relative) {
                    delete_task(&relative);
                    let path = Path::new(r"C:\Windows\System32\Tasks").join(&relative);
                    let _ = std::fs::remove_file(path);
                    log::warn!(
                        "persistence guard: removed new scheduled task {}",
                        relative.display()
                    );
                }
            }
            for name in service_names() {
                if !services.contains(&name) {
                    delete_service(&name);
                    log::warn!("persistence guard: removed new service {name}");
                }
            }
        }
    })
}
