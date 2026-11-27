//! Poll the driver's disk-guard counters and turn a refusal into an alert.
//!
//! The guard is the only part of this product that *refuses* a write at kernel
//! level, so silence after a refusal is the wrong behaviour: a person needs to
//! know that a boot-sector write was attempted and by which image. The driver
//! does not send an event for the refusal (it is at `DISPATCH_LEVEL` and has no
//! queue), so the service polls a counter instead. A counter is enough: the
//! alert is "this many writes were refused", and the log line beside it names
//! the service's own view of the event.
//!
//! The interval is short because the alternative is a refusal nobody sees until
//! the next six-hundred-second rootkit audit. Five seconds is one poll per
//! ordinary desktop wake-up and costs one IOCTL.

#![cfg(windows)]

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::IO::DeviceIoControl;

/// Start the poller. It runs for the life of the service.
pub fn start(data_dir: PathBuf) {
    std::thread::spawn(move || {
        let mut last: Option<u64> = None;
        loop {
            std::thread::sleep(Duration::from_secs(5));
            let Some(stats) = read_stats() else {
                continue;
            };
            match last {
                None => last = Some(stats.blocked),
                Some(seen) if stats.blocked > seen => {
                    let delta = stats.blocked - seen;
                    last = Some(stats.blocked);
                    log::error!(
                        "disk guard: {delta} write(s) to the first MiB refused; {} total, {} allowed",
                        stats.blocked,
                        stats.allowed
                    );
                    append_alert(&data_dir, delta, stats.blocked);
                }
                Some(seen) if stats.blocked < seen => {
                    // The driver was reloaded; the counter restarted.
                    last = Some(stats.blocked);
                }
                Some(_) => {}
            }
        }
    });
}

fn read_stats() -> Option<av_driver_proto::audit::DiskGuardStats> {
    let handle = crate::kernel_audit::open_audit_device()?;
    let mut stats = av_driver_proto::audit::DiskGuardStats::default();
    let mut returned = 0u32;
    let answer = unsafe {
        DeviceIoControl(
            handle,
            av_driver_proto::ioctl::IOCTL_DISK_GUARD_STATS,
            None,
            0,
            Some((&mut stats as *mut av_driver_proto::audit::DiskGuardStats).cast()),
            core::mem::size_of::<av_driver_proto::audit::DiskGuardStats>() as u32,
            Some(&mut returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    answer.ok()?;
    if stats.installed == 0 {
        return None;
    }
    Some(stats)
}

fn append_alert(data_dir: &std::path::Path, delta: u64, total: u64) {
    let line = serde_json::json!({
        "when": chrono::Utc::now().to_rfc3339(),
        "kind": "raw-disk-write",
        "path": "\\\\.\\PhysicalDrive0",
        "detail": format!(
            "{delta} write(s) to the first MiB were refused ({total} total)"
        ),
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
        log::warn!("disk guard alert could not be written to {}: {error}", file.display());
    }
}
