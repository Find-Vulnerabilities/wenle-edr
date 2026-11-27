//! Files that are another machine's disk or memory, not files on this one.
//!
//! A virtual-machine disk contains a guest filesystem. Scanning it treats the
//! guest's Windows, its downloads and whatever malware is inside it as if they
//! were files sitting on the host, and the verdict then applies to the disk
//! image: on 2026-11-18 the host product quarantined eleven VMware `.vmdk`
//! snapshot disks while the VM was running, and the vault then queued deletion
//! of the sources. That is a false positive with a data-loss shape.
//!
//! These files are not scanned, and the report says why. Nothing executable is
//! hidden by this: a `.vmdk` cannot be run, and the same bytes on a host (the
//! executable itself) are scanned as themselves.

use std::path::Path;

/// Extensions a hypervisor gives its disk, memory and suspend files.
///
/// Deliberately not `.vmx` or `.vmxf`: those are small configuration files the
/// engine can read normally, and skipping them would hide nothing worth hiding.
const EXTENSIONS: &[&str] = &[
    "vmdk", "vdi", "vhd", "vhdx", "avhdx", "vmem", "vmsn", "vswp", "vmss", "nvram",
    "vmsd", "vmrs",
];

/// Whether a path is a virtual-machine image.
pub fn is_image(path: &Path) -> bool {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    EXTENSIONS.contains(&extension.to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_and_memory_images_are_recognised() {
        assert!(is_image(Path::new(r"C:\VMs\Win11\Win11-000001-s001.vmdk")));
        assert!(is_image(Path::new(r"C:\VMs\Win11\Win11.vhdx")));
        assert!(is_image(Path::new(r"C:\VMs\Win11\Win11.vmem")));
        assert!(is_image(Path::new(r"C:\VMs\Win11\Win11-000001-s001.VMDK")));
    }

    #[test]
    fn diagnostics_and_traces_are_recognised() {
        assert!(is_diagnostic(Path::new(r"C:\Windows\Temp\crash.dmp")));
        assert!(is_diagnostic(Path::new(r"C:\logs\trace.etl")));
        assert!(is_diagnostic(Path::new(r"C:\logs\System.evtx")));
        assert!(!is_diagnostic(Path::new(r"C:\Windows\System32\kernel32.dll")));
    }

    #[test]
    fn ordinary_files_and_the_hypervisor_config_are_not() {
        assert!(!is_image(Path::new(r"C:\Users\w\Downloads\evil.exe")));
        assert!(!is_image(Path::new(r"C:\VMs\Win11\Win11.vmx")));
        assert!(!is_image(Path::new(r"C:\data\file.bin")));
    }
}

/// Extensions Windows gives crash dumps, event traces and report archives.
///
/// These are not programs and are not executed. Scanning them matches the feed
/// rules against fragments of memory and event payload: on 2026-11-24 a service
/// crash dump in `System32\config\systemprofile` was convicted as malicious
/// by a PowerShell-signature rule that matched bytes inside it. The bytes are
/// evidence of a crash, not files on this machine.
const DIAGNOSTIC: &[&str] = &["dmp", "mdmp", "hdmp", "etl", "evtx", "wer"];

/// Whether a path is a crash dump or a diagnostic trace.
pub fn is_diagnostic(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| DIAGNOSTIC.contains(&extension.to_ascii_lowercase().as_str()))
}
