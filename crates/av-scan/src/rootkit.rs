//! What the kernel is actually running.
//!
//! A rootkit's first job is to be loaded and then to be hard to see. User mode
//! cannot read `PsLoadedModuleList`, but it can ask the kernel for the module
//! list `NtQuerySystemInformation(SystemModuleInformation)` returns, and it can
//! compare each entry against the file on disk and against its signature. That
//! is enough to name four rootkit shapes without a kernel driver of our own:
//!
//! * a module whose path has no file on disk -- an unlinked driver, which is how
//!   a rootkit hides its image;
//! * a module loaded from a path a user or an installer writes -- the BYOVD
//!   drop pattern;
//! * a module whose signature is absent or invalid;
//! * a module signed by a key this machine does not trust.
//!
//! This is evidence, not proof: a legitimate third-party driver can be unsigned
//! on a test machine, so the severity says which shape was seen and the caller
//! decides. What it cannot see is a module that unlinked itself from the list
//! *and* patched the query -- that needs a kernel cross-view, and is recorded
//! as a limit rather than pretended away.

use std::path::{Path, PathBuf};

use av_authenticode::verdict::Unestablished;
use av_authenticode::Verdict;
use av_pe::PeFile;
use av_signatures::catalog::CatalogIndex;

/// One loaded kernel module, as the kernel reports it.
#[derive(Debug, Clone)]
pub struct Module {
    /// The image path, normalised to a DOS path where possible.
    pub path: PathBuf,
    /// Where the image is mapped.
    pub base: u64,
    /// How large it is.
    pub size: u32,
    /// `true` when the module's file exists on disk.
    pub file_present: bool,
}

/// What was found about one module.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The module path.
    pub path: PathBuf,
    /// The shape that was seen, as a stable word.
    pub kind: &'static str,
    /// One sentence for a report.
    pub detail: String,
    /// How much weight to put on it.
    pub severity: Severity,
}

/// How much weight a finding carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth knowing, not worth acting on.
    Note,
    /// A weak signal.
    Suspicious,
    /// A rootkit shape; remediate or investigate.
    Critical,
}

impl Severity {
    /// The word used in output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Suspicious => "suspicious",
            Severity::Critical => "critical",
        }
    }
}

/// The modules the kernel says are loaded.
pub fn loaded_modules() -> std::io::Result<Vec<Module>> {
    let mut buffer = vec![0u8; 256 * 1024];
    loop {
        let mut needed = 0u32;
        // SAFETY: `buffer` is a live allocation of `buffer.len()` bytes, and the
        // call writes at most `needed` bytes into it. A short buffer is answered
        // with STATUS_INFO_LENGTH_MISMATCH and the required size, not a write
        // past the end.
        let status = unsafe {
            NtQuerySystemInformation(
                SYSTEM_MODULE_INFORMATION,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut needed,
            )
        };
        if status == STATUS_INFO_LENGTH_MISMATCH {
            let grow = (needed as usize).max(buffer.len() * 2);
            buffer.resize(grow, 0);
            continue;
        }
        if status < 0 {
            return Err(std::io::Error::other(format!(
                "NtQuerySystemInformation(SystemModuleInformation) failed with {status:#x}"
            )));
        }
        break;
    }
    Ok(parse_modules(&buffer))
}

/// Parse the `RTL_PROCESS_MODULES` buffer.
fn parse_modules(buffer: &[u8]) -> Vec<Module> {
    const ENTRY: usize = 296;
    let count = read_u32(buffer, 0) as usize;
    let mut modules = Vec::with_capacity(count);
    for index in 0..count {
        let offset = 8 + index * ENTRY;
        if offset + ENTRY > buffer.len() {
            break;
        }
        let base = read_u64(buffer, offset + 16);
        let size = read_u32(buffer, offset + 24);
        // `FullPathName` starts at +40. `OffsetToFileName` points at the leaf
        // inside it; using that offset would throw the directory away and make
        // every module look unlinked, which is exactly what the first version
        // of this audit reported for ntoskrnl.exe.
        let name_start = offset + 40;
        let name_end = buffer[name_start..offset + 296]
            .iter()
            .position(|byte| *byte == 0)
            .map(|position| name_start + position)
            .unwrap_or(offset + 296);
        let name = String::from_utf8_lossy(&buffer[name_start..name_end]).into_owned();
        let path = normalise(&name);
        let file_present = path.is_file();
        modules.push(Module {
            path,
            base,
            size,
            file_present,
        });
    }
    modules
}

/// Turn the kernel's `\SystemRoot\...` spelling into a path on disk.
fn normalise(name: &str) -> PathBuf {
    let mut text = name.trim_matches('\0').to_string();
    if let Some(rest) = text.strip_prefix("\\SystemRoot") {
        text = format!("C:\\Windows{rest}");
    } else if let Some(rest) = text.strip_prefix("\\??\\") {
        text = rest.to_string();
    }
    PathBuf::from(text)
}

fn read_u16(buffer: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buffer[offset], buffer[offset + 1]])
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ])
}

fn read_u64(buffer: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buffer[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Paths a user or an installer writes, as opposed to the operating system.
fn user_writable(path: &Path) -> bool {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(extension.as_str(), "sys" | "dll" | "exe" | "ocx" | "cpl" | "efi") {
        return false;
    }
    let text = path.to_string_lossy().to_ascii_lowercase();
    // C:\Windows\Temp is user-writable even though it lives under Windows;
    // only the operating system's own image directories are not.
    if text.contains("\\windows\\system32\\") || text.contains("\\windows\\syswow64\\") {
        return false;
    }
    text.contains("\\users\\")
        || text.contains("\\temp\\")
        || text.contains("\\downloads\\")
        || text.contains("\\appdata\\")
        || text.contains("\\programdata\\")
        || text.contains("\\desktop\\")
}

/// Audit one module path: signature, presence, location.
pub fn audit_file(path: &Path) -> Vec<Finding> {
    audit_file_with(path, None)
}

/// [`audit_file`], with the machine's catalog store available.
///
/// A stock Windows driver carries no embedded Authenticode signature: its
/// publisher is proven by a catalog entry for its digest, and calling every one
/// of them "unsigned" is why the first run of this audit convicted cdrom.sys.
/// The catalog is the other half of the signature check, and when it answers
/// yes the embedded-signature question does not need asking.
pub fn audit_file_with(path: &Path, catalog: Option<&CatalogIndex>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !path.is_file() {
        findings.push(Finding {
            path: path.to_path_buf(),
            kind: "hidden-image",
            detail: "the module is loaded but its file is not on disk".to_string(),
            severity: Severity::Critical,
        });
        return findings;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return findings;
    };
    let verdict = av_authenticode::verify::verify_bytes(&bytes);
    let catalog_trusted = catalog.is_some_and(|index| {
        PeFile::parse(&bytes)
            .map(|pe| index.lists(&pe))
            .unwrap_or(false)
    });
    if !catalog_trusted {
    match &verdict {
        Verdict::Trusted(_) => {}
        Verdict::Untrusted { proof, reason } => findings.push(Finding {
            path: path.to_path_buf(),
            kind: "untrusted-signer",
            detail: format!(
                "signed by {} but the chain did not reach a trusted root ({reason:?})",
                proof.subject
            ),
            severity: Severity::Suspicious,
        }),
        Verdict::Invalid { reason } => findings.push(Finding {
            path: path.to_path_buf(),
            kind: "invalid-signature",
            detail: format!("the signature does not match the bytes on disk ({reason:?})"),
            severity: Severity::Critical,
        }),
        Verdict::Unsigned => findings.push(Finding {
            path: path.to_path_buf(),
            kind: "unsigned-driver",
            detail: "the image carries no Authenticode signature".to_string(),
            severity: Severity::Suspicious,
        }),
        Verdict::Undetermined { reason } => findings.push(Finding {
            path: path.to_path_buf(),
            kind: "unchecked-signature",
            detail: format!("the signature could not be established ({reason:?})"),
            severity: Severity::Note,
        }),
    }
    }
    if user_writable(path) {
        findings.push(Finding {
            path: path.to_path_buf(),
            kind: "user-path-driver",
            detail: "a kernel image loaded from a path a user can write".to_string(),
            severity: Severity::Critical,
        });
    }
    findings
}

/// Audit every loaded kernel module.
pub fn audit() -> std::io::Result<Vec<Finding>> {
    audit_with(None)
}

/// [`audit`], with the machine's catalog store available.
pub fn audit_with(catalog: Option<&CatalogIndex>) -> std::io::Result<Vec<Finding>> {
    let modules = loaded_modules()?;
    let mut findings = Vec::new();
    for module in modules {
        if !module.file_present {
            // A crash-dump stack driver lives in memory while the dump stack is
            // armed and has no file of its own; the Windows dump stack is the
            // only thing that produces this shape at a System32 path. An image
            // with no file anywhere else is the hidden-driver shape.
            let text = module.path.to_string_lossy().to_ascii_lowercase();
            let leaves = module
                .path
                .file_name()
                .map(|name| name.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let dump_stack = text.contains("\\windows\\system32\\drivers\\")
                && (leaves.starts_with("dump_") || leaves.starts_with("kd."));
            let system_path = text.contains("\\windows\\system32\\");
            let severity = if dump_stack {
                Severity::Note
            } else if system_path {
                Severity::Suspicious
            } else {
                Severity::Critical
            };
            findings.push(Finding {
                path: module.path.clone(),
                kind: "hidden-image",
                detail: format!(
                    "loaded at {:#x} ({} bytes) but no file exists at that path",
                    module.base, module.size
                ),
                severity,
            });
            continue;
        }
        findings.extend(audit_file_with(&module.path, catalog));
    }
    Ok(findings)
}

const SYSTEM_MODULE_INFORMATION: u32 = 11;
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        class: u32,
        information: *mut std::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_root_becomes_a_dos_path() {
        assert_eq!(
            normalise("\\SystemRoot\\system32\\ntoskrnl.exe"),
            PathBuf::from("C:\\Windows\\system32\\ntoskrnl.exe")
        );
        assert_eq!(
            normalise("\\??\\C:\\Windows\\System32\\drivers\\x.sys"),
            PathBuf::from("C:\\Windows\\System32\\drivers\\x.sys")
        );
    }

    #[test]
    fn a_driver_in_a_user_directory_is_user_writable() {
        assert!(user_writable(Path::new(
            "C:\\Users\\wenle\\Downloads\\evil.sys"
        )));
        assert!(user_writable(Path::new(
            "C:\\Windows\\Temp\\evil.sys"
        )));
        assert!(!user_writable(Path::new(
            "C:\\Windows\\System32\\drivers\\tcpip.sys"
        )));
        // Not a kernel image extension, so location alone is not the finding.
        assert!(!user_writable(Path::new(
            "C:\\Users\\wenle\\Downloads\\notes.txt"
        )));
    }

    #[test]
    fn modules_are_parsed_from_full_paths() {
        const ENTRY: usize = 296;
        let mut buffer = vec![0u8; 8 + ENTRY];
        buffer[0..4].copy_from_slice(&1u32.to_le_bytes());
        let base = 8 + 16;
        buffer[base..base + 8].copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        let size = 8 + 24;
        buffer[size..size + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        let path = b"C:\\Windows\\System32\\drivers\\test.sys";
        buffer[8 + 40..8 + 40 + path.len()].copy_from_slice(path);
        let modules = parse_modules(&buffer);
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].size, 0x1000);
        assert!(modules[0]
            .path
            .to_string_lossy()
            .ends_with("test.sys"));
    }
}
