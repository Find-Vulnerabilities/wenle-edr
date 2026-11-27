//! Outbound connection monitoring, without a kernel driver.
//!
//! Once every ten seconds the service reads the IPv4 TCP table
//! (`GetExtendedTcpTable`) and looks at connections in `ESTABLISHED`. A
//! connection is worth telling the user about when both halves are unusual:
//! the process lives somewhere a program has no business running from (a
//! temporary directory, Downloads, the public profile) and the remote port is
//! not one of the ports ordinary software uses to talk to the internet.
//!
//! # What this is not
//!
//! It is not a firewall and it does not block. It is also not a DNS monitor:
//! the table says where a connection went, not what name was asked for, and
//! pretending otherwise would need an ETW consumer and a much larger false
//! positive budget. What it does is put a line in `alerts.jsonl` — the same
//! file the ransomware canaries use, so the same notifier shows it — and a
//! warning in the log.
//!
//! The scoring is deliberately narrow because a network alert that fires on a
//! browser update is one a user learns to ignore. A connection from
//! `C:\Windows\System32\svchost.exe` to port 443 is not reported no matter how
//! often it happens; a connection from `%TEMP%\a.exe` to port 4444 is.

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How often the table is read.
const INTERVAL: Duration = Duration::from_secs(10);

/// Ports ordinary software uses. A connection to one of these is not, by
/// itself, a reason to tell a user anything.
const ORDINARY_PORTS: &[u16] = &[53, 80, 123, 443, 853, 3389, 8080, 8443];

/// Start the monitor. Called once from `Host::open`.
pub fn start(data_dir: PathBuf) {
    let _ = std::thread::Builder::new()
        .name("wenle-network".to_owned())
        .spawn(move || run(data_dir));
}

fn run(data_dir: PathBuf) {
    let mut reported: HashSet<(u32, Ipv4Addr, u16)> = HashSet::new();
    loop {
        std::thread::sleep(INTERVAL);
        match established() {
            Ok(connections) => {
                for connection in connections {
                    let Some(path) = crate::win32::process_image(connection.pid) else {
                        continue;
                    };
                    if !is_unusual(&path, connection.remote_port) {
                        continue;
                    }
                    let key = (connection.pid, connection.remote, connection.remote_port);
                    if !reported.insert(key) {
                        continue;
                    }
                    log::warn!(
                        "network: {} (pid {}) has an established connection to {}:{}",
                        path.display(),
                        connection.pid,
                        connection.remote,
                        connection.remote_port
                    );
                    append_alert(&data_dir, &path, connection.remote, connection.remote_port);
                }
                // A process that exits and is started again can reuse its pid,
                // and a stale entry would silence the second process's first
                // connection. The set is small; clearing it once a minute is
                // cheaper than tracking process creation times here.
                if reported.len() > 4096 {
                    reported.clear();
                }
            }
            Err(error) => log::debug!("network table could not be read: {error}"),
        }
    }
}

/// One established IPv4 connection.
struct Connection {
    pid: u32,
    remote: Ipv4Addr,
    remote_port: u16,
}

/// Whether a program in `path` talking to `remote_port` is unusual enough to
/// report.
///
/// Split out from the table walk so the decision can be tested without a
/// network: the table is the operating system's answer and this is the
/// product's.
fn is_unusual(path: &Path, remote_port: u16) -> bool {
    if ORDINARY_PORTS.contains(&remote_port) {
        return false;
    }
    let lowered = path.to_string_lossy().to_ascii_lowercase();
    lowered.contains(r"\temp\")
        || lowered.contains(r"\downloads\")
        || lowered.contains(r"\users\public\")
        || lowered.contains(r"\appdata\local\temp\")
}

/// Read the established IPv4 connections, skipping loopback and private
/// destinations: those are the machine talking to itself or to its own LAN,
/// and a connection to a printer is not a security event.
#[cfg(windows)]
fn established() -> Result<Vec<Connection>, String> {
    use std::ffi::c_void;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    let mut size = 0u32;
    // First call sizes the buffer. Its return value is expected to be
    // ERROR_INSUFFICIENT_BUFFER; anything else is still answered by the second
    // call and its size is what matters.
    unsafe {
        let _ = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; size as usize];
    let result = unsafe {
        GetExtendedTcpTable(
            Some(buffer.as_mut_ptr().cast::<c_void>()),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if result != 0 {
        return Err(format!("GetExtendedTcpTable returned {result}"));
    }
    if buffer.len() < 4 {
        return Ok(Vec::new());
    }
    let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let header = 4usize;
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let mut connections = Vec::new();
    for index in 0..count {
        let offset = header + index * row_size;
        if offset + row_size > buffer.len() {
            break;
        }
        // The table is packed by the operating system; read it as bytes rather
        // than forming a reference to a potentially unaligned struct.
        let row = unsafe {
            std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const MIB_TCPROW_OWNER_PID)
        };
        // MIB_TCP_STATE_ESTABLISHED is 5 in `iprtrmib.h`.
        if row.dwState != 5 {
            continue;
        }
        let remote = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        if remote.is_loopback() || remote.is_private() || remote.is_link_local() {
            continue;
        }
        let remote_port = u16::from_be((row.dwRemotePort & 0xffff) as u16);
        if ORDINARY_PORTS.contains(&remote_port) {
            continue;
        }
        connections.push(Connection {
            pid: row.dwOwningPid,
            remote,
            remote_port,
        });
    }
    Ok(connections)
}

#[cfg(not(windows))]
fn established() -> Result<Vec<Connection>, String> {
    Ok(Vec::new())
}

/// Append one alert line for the notifier, the same shape the canaries write.
fn append_alert(data_dir: &Path, path: &Path, remote: Ipv4Addr, port: u16) {
    let line = serde_json::json!({
        "when": chrono::Utc::now().to_rfc3339(),
        "kind": "network",
        "path": path.display().to_string(),
        "detail": format!("connection to {remote}:{port}"),
    });
    let file = data_dir.join("alerts.jsonl");
    let result = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
        .and_then(|mut file| {
            writeln!(file, "{line}")?;
            file.sync_data()
        });
    if let Err(error) = result {
        log::warn!("network alert could not be written: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_browser_port_is_ordinary_wherever_the_program_lives() {
        assert!(!is_unusual(Path::new(r"C:\Users\a\AppData\Local\Temp\x.exe"), 443));
        assert!(!is_unusual(Path::new(r"C:\Users\a\Downloads\x.exe"), 8080));
    }

    #[test]
    fn a_downloaded_program_on_an_unusual_port_is_reported() {
        assert!(is_unusual(Path::new(r"C:\Users\a\Downloads\x.exe"), 4444));
        assert!(is_unusual(Path::new(r"C:\Users\a\AppData\Local\Temp\x.exe"), 1337));
        assert!(!is_unusual(Path::new(r"C:\Windows\System32\svchost.exe"), 4444));
    }
}
