//! Post the product's desktop notifications without the window.
//!
//! The window already posts these while it is running, which is exactly the
//! problem: a user who never opened it — or closed it to the notification area
//! and then exited — was told nothing when a download was quarantined. This
//! binary is started at sign-in instead of the window. It holds no window, no
//! tray icon and no egui context; it asks the service for the quarantine list
//! every second and posts a toast for an entry that was not in the previous
//! answer.
//!
//! # Why polling and not the event stream
//!
//! The control pipe serves each client on its own thread, but events are
//! produced by `Host::drain` *per connection*: two clients do not both receive
//! one detection, the first to drain takes it. A notifier that subscribed
//! would race the window for events and make whichever lost silent. The
//! quarantine list is the durable record of what was taken, so polling it is
//! the version that cannot miss a block because another front end was open.
//!
//! The cost is stated rather than hidden: a detection that is blocked but not
//! quarantined (an execution the kernel refused) is not in this list. Those
//! are still in the window's event stream, and a later version can ask the
//! service for its recent detections without changing this shape.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use av_ipc::{Client, Incoming, Reply, Request, PIPE_NAME};
use av_quarantine::{EntryStatus, QuarantineId};

mod tray;

fn main() {
    if !claim_single_instance() {
        return;
    }
    let once = std::env::args().any(|argument| argument == "--once");
    log("notifier starting");
    let _ = tray::start();
    let mut seen: HashSet<QuarantineId> = HashSet::new();
    let mut primed = false;
    let mut alert_offset: Option<u64> = Some(alert_file_length());

    let mut tick = 0u64;
    loop {
        // The quarantine list is a durable record, not a hot path: fifteen seconds
        // is soon enough for a toast, and it keeps a vault with thousands of
        // entries from being listed every second. Alerts stay on the one-second
        // tick because they are the time-sensitive half.
        if tick % 15 == 0 {
            match poll_once(&mut seen, primed) {
                Ok(entries) => {
                    if !primed {
                        log(&format!(
                            "primed with {} existing quarantine entr{}",
                            entries,
                            if entries == 1 { "y" } else { "ies" }
                        ));
                        primed = true;
                    }
                    if once {
                        return;
                    }
                }
                Err(error) => {
                    log(&format!("service not reachable: {error}"));
                    if once {
                        return;
                    }
                }
            }
        }
        poll_alerts(&mut alert_offset);
        tick = tick.wrapping_add(1);
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Read the service's ransomware alerts and announce the new ones.
///
/// The file is the channel because a canary alert belongs to the user whose
/// folder was touched, and the service runs in session 0 where no toast can be
/// shown. The first look starts at the current end of the file: an installation
/// must not replay old alerts, for the same reason the quarantine poll seeds
/// itself.
/// The alert file's current length, or zero when it does not exist yet.
///
/// Read before the loop starts, not on the first poll: a canary can be touched
/// between those two moments, and treating the first successful look as the
/// baseline loses exactly that alert.
fn alert_file_length() -> u64 {
    let Some(program_data) = std::env::var_os("PROGRAMDATA") else {
        return 0;
    };
    std::fs::metadata(
        PathBuf::from(program_data)
            .join("WenleAV")
            .join("alerts.jsonl"),
    )
    .map(|metadata| metadata.len())
    .unwrap_or(0)
}

fn poll_alerts(offset: &mut Option<u64>) {
    let Some(program_data) = std::env::var_os("PROGRAMDATA") else {
        return;
    };
    let path = PathBuf::from(program_data)
        .join("WenleAV")
        .join("alerts.jsonl");
    let Ok(metadata) = std::fs::metadata(&path) else {
        return;
    };
    let length = metadata.len();
    match offset {
        None => {
            *offset = Some(length);
            return;
        }
        Some(seen) if length < *seen => {
            *offset = Some(0);
        }
        Some(_) => {}
    }
    let start = offset.unwrap_or(0);
    if length == start {
        return;
    }
    let Ok(mut file) = std::fs::File::open(&path) else {
        return;
    };
    use std::io::{Read, Seek, SeekFrom};
    if file.seek(SeekFrom::Start(start)).is_err() {
        return;
    }
    let mut text = String::new();
    if file.read_to_string(&mut text).is_err() {
        return;
    }
    *offset = Some(length);
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let file = value.get("path").and_then(|v| v.as_str()).unwrap_or("a file");
        let detail = value.get("detail").and_then(|v| v.as_str()).unwrap_or("changed");
        log(&format!("ransomware alert: {file} ({detail})"));
        let body = format!("{file} — {detail}. Files in that folder may be encrypted.");
        if let Err(error) = show("Ransomware canary triggered", &body) {
            log(&format!("toast was not posted: {error}"));
        }
    }
}

/// One ask of the vault, announcing every entry that was not there before.
///
/// Returns how many entries the service listed, which the caller uses to
/// distinguish "the first answer is the baseline" from "a block happened".
fn poll_once(seen: &mut HashSet<QuarantineId>, primed: bool) -> Result<usize, String> {
    let connection = av_service::pipe::PipeConnection::connect_to(PIPE_NAME)
        .map_err(|error| error.to_string())?;
    let mut client = Client::new(connection);
    let wanted = client
        .send(Request::QuarantineList { limit: Some(64) })
        .map_err(|error| error.to_string())?;

    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if std::time::Instant::now() > deadline {
            return Err("the service did not answer the quarantine list".to_owned());
        }
        let incoming = client.recv().map_err(|error| error.to_string())?;
        for message in incoming {
            let Incoming::Reply { id, reply } = message else {
                continue;
            };
            if id != wanted {
                continue;
            }
            let Reply::QuarantineList(listing) = reply else {
                return Err("the service answered with something else".to_owned());
            };
            let mut fresh = Vec::new();
            for entry in &listing.entries {
                if !seen.insert(entry.id) {
                    continue;
                }
                if primed && entry.status == EntryStatus::Quarantined {
                    fresh.push(entry.clone());
                }
            }
            if !fresh.is_empty() {
                announce(&fresh);
            }
            return Ok(listing.entries.len());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One toast for a burst, with the newest file named.
fn announce(entries: &[av_quarantine::QuarantineEntry]) {
    let newest = &entries[0];
    let family = newest
        .threat
        .as_ref()
        .map(|threat| threat.to_string())
        .unwrap_or_else(|| "malicious file".to_owned());
    let body = if entries.len() == 1 {
        format!("{} — {}", newest.file_name, family)
    } else {
        format!(
            "{} and {} more — {}",
            newest.file_name,
            entries.len() - 1,
            family
        )
    };
    log(&format!("announcing {} ({})", newest.file_name, family));
    if let Err(error) = show("Threat blocked by Wenle", &body) {
        log(&format!("toast was not posted: {error}"));
    }
}

#[cfg(windows)]
fn show(title: &str, body: &str) -> Result<(), String> {
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

    let xml = toast_xml(title, body);
    unsafe {
        match RoInitialize(RO_INIT_MULTITHREADED) {
            Ok(()) => {}
            Err(error) if error.code() == windows::Win32::Foundation::RPC_E_CHANGED_MODE => {}
            Err(error) => return Err(format!("WinRT could not start: {error}")),
        }
        let document = XmlDocument::new().map_err(|error| error.to_string())?;
        document
            .LoadXml(&HSTRING::from(xml))
            .map_err(|error| format!("the notification was malformed: {error}"))?;
        let notification =
            ToastNotification::CreateToastNotification(&document).map_err(|error| error.to_string())?;
        let _ = notification.SetTag(&HSTRING::from("blocked"));
        let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
            av_core::APP_USER_MODEL_ID,
        ))
        .map_err(|error| format!("no notifier: {error}"))?;
        notifier
            .Show(&notification)
            .map_err(|error| format!("the shell refused it: {error}"))
    }
}

#[cfg(not(windows))]
fn show(_title: &str, _body: &str) -> Result<(), String> {
    Err("there is no shell on this platform".to_owned())
}

/// The toast document, with the five reserved characters escaped.
fn toast_xml(title: &str, body: &str) -> String {
    fn escape(text: &str, out: &mut String) {
        for ch in text.chars() {
            match ch {
                '&' => out.push_str("&amp;"),
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '"' => out.push_str("&quot;"),
                '\'' => out.push_str("&apos;"),
                '\t' | '\n' | '\r' => out.push(ch),
                c if (c as u32) < 0x20 => {}
                c => out.push(c),
            }
        }
    }
    let mut xml = String::with_capacity(title.len() + body.len() + 256);
    xml.push_str(r#"<toast duration="long"><visual><binding template="ToastGeneric"><text>"#);
    escape(title, &mut xml);
    xml.push_str("</text><text>");
    escape(body, &mut xml);
    xml.push_str(
        r#"</text></binding></visual><audio src="ms-winsoundevent:Notification.Default"/></toast>"#,
    );
    xml
}

/// A named mutex, so a second sign-in or a double-click does not double-post.
#[cfg(windows)]
fn claim_single_instance() -> bool {
    use windows::core::w;
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;

    unsafe {
        let handle = CreateMutexW(None, true, w!("Global\\WenleNotify"));
        if handle.is_err() {
            return true; // A mutex that cannot be created is not a reason to stay silent.
        }
        GetLastError() != ERROR_ALREADY_EXISTS
    }
}

#[cfg(not(windows))]
fn claim_single_instance() -> bool {
    true
}

/// A durable line for support, in the user's own profile because this process
/// is not the service and must not write into ProgramData.
fn log(line: &str) {
    let Some(local) = std::env::var_os("LOCALAPPDATA") else {
        return;
    };
    let directory = PathBuf::from(local).join("WenleAV");
    let _ = std::fs::create_dir_all(&directory);
    let path = directory.join("notifier.log");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        use std::io::Write;
        let _ = writeln!(
            file,
            "{} {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            line
        );
    }
}
