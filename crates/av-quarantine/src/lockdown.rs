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

use std::path::Path;

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
