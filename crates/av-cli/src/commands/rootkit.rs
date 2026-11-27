//! `wenle rootkit`: what the kernel is running, and which of it looks hidden.
//!
//! The audit itself is in `av_scan::rootkit`; this is only the report. It exits
//! malicious when a critical shape was seen, so a script can act on it, and it
//! names the shape rather than only the file: "unsigned driver" and "driver
//! loaded from Downloads" are different problems with different next steps.

use anyhow::Result;

use av_scan::rootkit::{self, Severity};

use crate::cli::{Globals, RootkitArgs};
use crate::commands::Context;
use crate::exit::Exit;

/// Run `wenle rootkit`.
pub fn run(args: &RootkitArgs, _globals: &Globals, context: &Context) -> Result<Exit> {
    let catalog = av_signatures::catalog::CatalogIndex::from_store_cached(&context.paths.cache_dir).ok();
    let mut findings = match &args.file {
        Some(file) => rootkit::audit_file_with(file, catalog.as_ref()),
        None => rootkit::audit_with(catalog.as_ref())?,
    };

    // The kernel's own module list, cross-viewed against the user-mode list and
    // the files on disk. This is the half of the audit that a rootkit hiding
    // itself from `NtQuerySystemInformation` cannot hide from: the list comes
    // from `ZwQuerySystemInformation` inside the kernel, over the audit device.
    #[cfg(windows)]
    if args.file.is_none() {
        if let Some(kernel) = kernel_module_list() {
            let user_paths: std::collections::HashSet<String> = rootkit::loaded_modules()
                .unwrap_or_default()
                .iter()
                .filter_map(|module| disk_path_of(&module.path.to_string_lossy()))
                .map(|path| path.to_string_lossy().to_ascii_lowercase())
                .collect();
            for module in kernel {
                let raw = String::from_utf8_lossy(&module.path)
                    .trim_end_matches('\0')
                    .to_string();
                let Some(disk) = disk_path_of(&raw) else {
                    continue;
                };
                if !disk.is_file() {
                    findings.push(av_scan::rootkit::Finding {
                        path: disk,
                        kind: "hidden-image",
                        detail: format!(
                            "loaded at {:#x} ({} bytes) in the kernel module list but no file exists: {raw}",
                            module.image_base, module.image_size
                        ),
                        severity: av_scan::rootkit::Severity::Suspicious,
                    });
                } else if !user_paths.contains(&disk.to_string_lossy().to_ascii_lowercase()) {
                    findings.push(av_scan::rootkit::Finding {
                        path: disk,
                        kind: "module-view-mismatch",
                        detail: format!(
                            "in the kernel module list at {:#x} but absent from the user-mode module list",
                            module.image_base
                        ),
                        severity: av_scan::rootkit::Severity::Suspicious,
                    });
                }
            }
        }
        if let Some(hooks) = kernel_hooks() {
            let image = std::path::PathBuf::from(
                std::env::var_os("SystemRoot")
                    .map(|root| std::path::PathBuf::from(root).join("System32\\ntoskrnl.exe"))
                    .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\System32\ntoskrnl.exe")),
            );
            for hook in hooks {
                let name = String::from_utf8_lossy(&hook.name)
                    .trim_end_matches('\0')
                    .to_string();
                // The disk file is the reference, not a shape: read the same
                // export out of ntoskrnl.exe and compare sixteen bytes. A
                // missing export (a hotpatch helper, a name this build does not
                // have) is skipped rather than guessed at.
                let disk = disk_export_prologue(&image, &name);
                if let Some(disk) = disk {
                    if disk != hook.prologue {
                        findings.push(av_scan::rootkit::Finding {
                            path: image.clone(),
                            kind: "inline-hook",
                            detail: format!(
                                "{name} at {:#x}: runtime {} != disk {}",
                                hook.address,
                                hex_bytes(&hook.prologue[..8]),
                                hex_bytes(&disk[..8])
                            ),
                            severity: av_scan::rootkit::Severity::Critical,
                        });
                    }
                }
            }
        }
    }

    if args.all && args.file.is_none() {
        for module in rootkit::loaded_modules()? {
            println!(
                "{:#018x} {:>9}  {}",
                module.base,
                module.size,
                module.path.display()
            );
        }
        println!();
        if let Some(hooks) = kernel_hooks() {
            for hook in hooks {
                let name = String::from_utf8_lossy(&hook.name)
                    .trim_end_matches('\0')
                    .to_string();
                let disk = disk_export_prologue(
                    &std::path::PathBuf::from(
                        std::env::var_os("SystemRoot")
                            .map(|root| std::path::PathBuf::from(root).join("System32\\ntoskrnl.exe"))
                            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Windows\System32\ntoskrnl.exe")),
                    ),
                    &name,
                );
                println!(
                    "hook {:28} runtime {}  disk {}",
                    name,
                    hex_bytes(&hook.prologue[..8]),
                    disk.map(|bytes| hex_bytes(&bytes[..8]))
                        .unwrap_or_else(|| "not found".to_string())
                );
            }
            println!();
        }
    }

    for finding in &findings {
        println!(
            "{:<10}  {:<18}  {}\n            {}",
            finding.severity.as_str(),
            finding.kind,
            finding.path.display(),
            finding.detail
        );
    }
    if findings.is_empty() {
        println!("no rootkit shapes found");
    } else {
        let critical = findings
            .iter()
            .filter(|finding| finding.severity == Severity::Critical)
            .count();
        println!(
            "\n{} finding(s), {critical} critical",
            findings.len()
        );
    }

    let critical = findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical);
    Ok(if critical {
        Exit::Malicious
    } else {
        Exit::Clean
    })
}

/// The loaded modules the kernel reports, through the audit control device.
///
/// `None` when the device is absent (an older driver) or the answer is not the
/// fixed structure: the caller then reports only the user-mode view, which is
/// what the command did before this existed.
/// The same export's first sixteen bytes in a file on disk.
fn disk_export_prologue(path: &std::path::Path, name: &str) -> Option<[u8; 16]> {
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

/// The runtime prologues of the ntoskrnl exports, through the audit device.
#[cfg(windows)]
fn kernel_hooks() -> Option<Vec<av_driver_proto::audit::KernelHook>> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let name: Vec<u16> = std::ffi::OsStr::new(r"\\.\WenleAvAudit")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
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
    .ok()?;
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

#[cfg(windows)]
fn kernel_module_list() -> Option<Vec<av_driver_proto::audit::KernelModule>> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    let name: Vec<u16> = std::ffi::OsStr::new(r"\\.\WenleAvAudit")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let handle = unsafe {
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
    .ok()?;
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

/// Turn a path the kernel loader reports into a path on this machine, when it
/// is one this machine can check.
///
/// The loader holds `\SystemRoot\...` for boot images and `\??\C:\...` for
/// others. `\Device\...` needs a volume mount to resolve and is left alone
/// rather than guessed at.
fn disk_path_of(raw: &str) -> Option<std::path::PathBuf> {
    let raw = raw.trim_end_matches('\0');
    // The user-mode module list already returns DOS paths.
    if raw.len() >= 3 && raw.as_bytes()[1] == b':'
    {
        return Some(std::path::PathBuf::from(raw));
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with(r"\systemroot\") {
        let root = std::env::var_os("SystemRoot")?;
        return Some(std::path::PathBuf::from(root).join(&raw[12..]));
    }
    if let Some(rest) = raw.strip_prefix(r"\??\") {
        return Some(std::path::PathBuf::from(rest));
    }
    None
}

#[cfg(test)]
mod kernel_view_tests {
    use super::*;

    #[test]
    fn systemroot_paths_become_windows_paths() {
        let path = disk_path_of(r"\SystemRoot\system32\ntoskrnl.exe").expect("resolves");
        assert!(path.ends_with("system32\ntoskrnl.exe"));
        assert!(path.is_absolute());
    }

    #[test]
    fn dos_namespace_paths_are_stripped_and_device_paths_are_left_alone() {
        assert_eq!(
            disk_path_of(r"\??\C:\Windows\System32\drivers\x.sys"),
            Some(std::path::PathBuf::from(r"C:\Windows\System32\drivers\x.sys"))
        );
        assert!(disk_path_of(r"\Device\HarddiskVolume1\Windows\x.sys").is_none());
    }
}
