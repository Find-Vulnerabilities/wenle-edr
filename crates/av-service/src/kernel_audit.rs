//! The kernel half of the rootkit audit.
//!
//! `av_scan::rootkit` reads the module list the way a user-mode program can:
//! `NtQuerySystemInformation`, disk names, catalog signatures. A rootkit that
//! unlinks itself from the list user mode is shown is invisible to exactly that
//! read. This module asks the audit control device instead, where the list is
//! `ZwQuerySystemInformation`'s answer inside the kernel, and cross-views it
//! against the user-mode list and the files on disk.
//!
//! It also reads the runtime prologues of a fixed set of ntoskrnl exports and
//! reports one that starts with a jump. That is the inline-hook shape: the
//! function body on disk begins with the compiler's prologue, not `E9` or
//! `FF 25`. The check is deliberately a shape, not a byte-for-byte comparison,
//! because the disk file's export RVA is not the runtime address and mapping one
//! to the other needs a PE parse that belongs in a later version. A false
//! positive here is a critical finding, so the two jump forms are the only ones
//! reported.

#![cfg(windows)]

use std::path::{Path, PathBuf};

use av_scan::rootkit::{Finding, Severity};

/// Ask the audit device for the kernel module list and the export prologues.
///
/// An absent device is not an error: it is a machine running an older driver,
/// which still has the user-mode audit. The caller keeps whatever it had.
pub fn findings() -> Vec<Finding> {
    let mut findings = Vec::new();
    let modules = match kernel_module_list() {
        Some(modules) => modules,
        None => return findings,
    };
    let user_paths: std::collections::HashSet<String> = av_scan::rootkit::loaded_modules()
        .unwrap_or_default()
        .iter()
        .filter_map(|module| disk_path_of(&module.path.to_string_lossy()))
        .map(|path| path.to_string_lossy().to_ascii_lowercase())
        .collect();
    for module in modules {
        let raw = String::from_utf8_lossy(&module.path)
            .trim_end_matches('\0')
            .to_string();
        let Some(disk) = disk_path_of(&raw) else {
            continue;
        };
        if !disk.is_file() {
            findings.push(Finding {
                path: disk,
                kind: "hidden-image",
                detail: format!(
                    "loaded at {:#x} ({} bytes) in the kernel module list but no file exists: {raw}",
                    module.image_base, module.image_size
                ),
                severity: Severity::Suspicious,
            });
        } else if !user_paths.contains(&disk.to_string_lossy().to_ascii_lowercase()) {
            findings.push(Finding {
                path: disk,
                kind: "module-view-mismatch",
                detail: format!(
                    "in the kernel module list at {:#x} but absent from the user-mode module list",
                    module.image_base
                ),
                severity: Severity::Suspicious,
            });
        }
    }
    let image = ntoskrnl_path();
    for hook in kernel_hooks().unwrap_or_default() {
        let name = String::from_utf8_lossy(&hook.name)
            .trim_end_matches('\0')
            .to_string();
        // The disk file is the reference, not a shape: read the same export
        // out of ntoskrnl.exe and compare sixteen bytes. A missing export is
        // skipped rather than guessed at.
        if let Some(disk) = disk_export_prologue(&image, &name) {
            if disk != hook.prologue {
                findings.push(Finding {
                    path: image.clone(),
                    kind: "inline-hook",
                    detail: format!(
                        "{name} at {:#x}: runtime {} != disk {}",
                        hook.address,
                        hex_bytes(&hook.prologue[..8]),
                        hex_bytes(&disk[..8])
                    ),
                    severity: Severity::Critical,
                });
            }
        }
    }
    findings
}

/// The same export's first sixteen bytes in a file on disk.
fn disk_export_prologue(path: &Path, name: &str) -> Option<[u8; 16]> {
    let data = std::fs::read(path).ok()?;
    let pe = av_pe::PeFile::parse(&data).ok()?;
    let exports = av_pe::exports::read(&pe);
    let detail = exports
        .details()
        .iter()
        .find(|detail| detail.name() == Some(name.as_bytes()))?;
    let offset = usize::try_from(detail.offset()).ok()?;
    let bytes = data.get(offset..offset + 16)?;
    let mut prologue = [0u8; 16];
    prologue.copy_from_slice(bytes);
    Some(prologue)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
}

fn ntoskrnl_path() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("System32\\ntoskrnl.exe"))
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows\System32\ntoskrnl.exe"))
}

/// Turn a path the loader reports into one this machine can check.
fn disk_path_of(raw: &str) -> Option<PathBuf> {
    let raw = raw.trim_end_matches('\0');
    if raw.len() >= 3 && raw.as_bytes()[1] == b':' {
        return Some(PathBuf::from(raw));
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        let root = std::env::var_os("SystemRoot")?;
        return Some(PathBuf::from(root).join(&raw[12..]));
    }
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        return Some(PathBuf::from(rest));
    }
    None
}

pub(crate) fn open_audit_device() -> Option<windows::Win32::Foundation::HANDLE> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let name: Vec<u16> = std::ffi::OsStr::new(r"\\.\WenleAvAudit")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    unsafe {
        CreateFileW(
            PCWSTR(name.as_ptr()),
            0xC000_0000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .ok()
}

fn kernel_module_list() -> Option<Vec<av_driver_proto::audit::KernelModule>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::IO::DeviceIoControl;

    let handle = open_audit_device()?;
    let mut list = Box::new(av_driver_proto::audit::KernelModuleList::empty());
    let mut returned = 0u32;
    let answer = unsafe {
        DeviceIoControl(
            handle,
            av_driver_proto::ioctl::IOCTL_KERNEL_MODULES,
            None,
            0,
            Some((&mut *list as *mut av_driver_proto::audit::KernelModuleList).cast()),
            av_driver_proto::audit::KERNEL_MODULE_LIST_BYTES as u32,
            Some(&mut returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    answer.ok()?;
    let count = (list.count as usize).min(av_driver_proto::audit::MAX_MODULES);
    Some(list.modules[..count].to_vec())
}

fn kernel_hooks() -> Option<Vec<av_driver_proto::audit::KernelHook>> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::IO::DeviceIoControl;

    let handle = open_audit_device()?;
    let mut list = Box::new(av_driver_proto::audit::KernelHookList::empty());
    let mut returned = 0u32;
    let answer = unsafe {
        DeviceIoControl(
            handle,
            av_driver_proto::ioctl::IOCTL_INLINE_HOOKS,
            None,
            0,
            Some((&mut *list as *mut av_driver_proto::audit::KernelHookList).cast()),
            av_driver_proto::audit::KERNEL_HOOK_LIST_BYTES as u32,
            Some(&mut returned),
            None,
        )
    };
    unsafe {
        let _ = CloseHandle(handle);
    }
    answer.ok()?;
    let count = (list.count as usize).min(av_driver_proto::audit::MAX_HOOKS);
    Some(list.hooks[..count].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_and_systemroot_paths_resolve() {
        assert_eq!(
            disk_path_of(r"C:\Windows\System32\drivers\x.sys"),
            Some(PathBuf::from(r"C:\Windows\System32\drivers\x.sys"))
        );
        let path = disk_path_of(r"\SystemRoot\system32\ntoskrnl.exe").expect("resolves");
        assert!(path.ends_with("system32\\ntoskrnl.exe"));
    }

    #[test]
    fn device_paths_are_not_guessed_at() {
        assert!(disk_path_of(r"\Device\HarddiskVolume1\Windows\x.sys").is_none());
    }
}
