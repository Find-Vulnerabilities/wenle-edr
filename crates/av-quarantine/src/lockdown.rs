//! Deny access to an original that could not be deleted.
//!
//! This is the user-mode half of the "still on disk" state. The vault already
//! holds the bytes; this makes the path useless to the account that can still
//! see it. It is deliberately not the only defence: an administrator can take
//! ownership and rewrite the DACL, and a process with `SeBackupPrivilege` can
//! ask the kernel to ignore it. A minifilter matching the file by ID is what
//! closes those holes; this module closes the ordinary double-click, Explorer,
//! PowerShell, archive-reader and `Start-Process` routes while the driver work
//! is not available.
//!
//! # Why `icacls` and not a hand-written DACL
//!
//! The localised names are the trap: `Users`, `Administrators` and
//! `Authenticated Users` are display names, and a build that hard-codes them
//! fails on a non-English Windows. The SIDs are stable. `icacls` is the
//! supported tool for applying a DACL to a file that may still have an open
//! handle (a DACL write does not need the data handle), and it reports a
//! failure through its exit code rather than through a partially applied ACE.
//! The deny is to the SIDs of the ordinary user groups, not `Everyone`: SYSTEM
//! is in `Everyone`, and the service must still be able to delete the file when
//! the handle is released.

use std::path::{Path, PathBuf};

/// Move an undeletable original into the directory the driver refuses.
///
/// The vault already holds the bytes, and a rename on the same volume is the
/// one user-mode operation that both keeps the data and takes the original
/// path away. It can fail when the file is open without `FILE_SHARE_DELETE`;
/// the caller then falls back to the deny DACL. The driver's create and section
/// callbacks refuse this directory to everything except the product, so the
/// file cannot be opened from Explorer, PowerShell, an archive reader or a
/// memory-mapped image even by an administrator.
pub fn move_to_blocked(path: &Path) -> std::io::Result<PathBuf> {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("WenleAV")
        .join("blocked");
    std::fs::create_dir_all(&base)?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "quarantined".to_string());
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let target = base.join(format!("{stamp}-{file_name}.blocked"));
    std::fs::rename(path, &target)?;
    if let Err(error) = lock_down(&target) {
        log::warn!(
            "{} was moved to the blocked directory but its DACL was not tightened: {error}",
            target.display()
        );
    }
    Ok(target)
}

/// Deny read/execute/write/delete to every interactive user group, keep SYSTEM
/// full control, and ask the kernel to finish the deletion at the next boot.
///
/// Returns the first error rather than a bool: a caller that cannot tell "the
/// ACL was applied" from "icacls was missing" cannot tell a user whether the
/// file is actually blocked.
pub fn lock_down(path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let status = std::process::Command::new("icacls.exe")
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(F)",
                "/deny",
                "*S-1-5-32-545:(F)",
                "*S-1-5-11:(F)",
                "*S-1-5-32-544:(F)",
                "*S-1-5-4:(F)",
            ])
            .status()?;
        if !status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("icacls refused to lock down {}", path.display()),
            ));
        }

        // Make the file go away at the next boot even if the handle is never
        // released. `MoveFileExW` with a null destination queues the deletion;
        // the bytes remain until then, which is the state the dialog describes.
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated and outlives the call; a null
        // destination with MOVEFILE_DELAY_UNTIL_REBOOT is the documented
        // "delete at reboot" form.
        let queued =
            unsafe { MoveFileExW(PCWSTR(wide.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
        if let Err(error) = queued {
            log::warn!(
                "{} could not be queued for deletion at reboot: {error}",
                path.display()
            );
        }
    }
    #[cfg(not(windows))]
    {
        let _ = path;
    }
    Ok(())
}
