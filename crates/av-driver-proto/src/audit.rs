//! The fixed-size payloads the audit control device returns.
//!
//! The device is asked with `METHOD_BUFFERED`, so these structures are copied
//! between user mode and kernel memory by the I/O manager. Every field is a
//! fixed width and the array is bounded: an answer that could grow without a
//! limit is an answer a caller cannot size a buffer for.

/// Bytes reserved for one module's path, ANSI, including the NUL.
pub const MODULE_PATH_BYTES: usize = 260;

/// How many loaded modules one answer carries.
///
/// A Windows machine loads a few hundred; the list is for a cross-view check,
/// not for an inventory, and a caller that needs the rest can ask again. The
/// bound keeps the response under 18 KB.
pub const MAX_MODULES: usize = 64;

/// One entry of `RTL_PROCESS_MODULES`, copied into a stable ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelModule {
    /// Where the image is loaded in kernel virtual address space.
    pub image_base: u64,
    /// The image's size, from the loader's own record.
    pub image_size: u32,
    /// The path the loader holds: `\SystemRoot\...` or `\??\C:\...`.
    pub path: [u8; MODULE_PATH_BYTES],
}

/// The answer to [`crate::ioctl::IOCTL_KERNEL_MODULES`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelModuleList {
    /// How many entries in `modules` are filled.
    pub count: u32,
    /// The modules, in load order.
    pub modules: [KernelModule; MAX_MODULES],
}

impl KernelModuleList {
    /// A zeroed list, for a caller that writes into a buffer.
    pub const fn empty() -> Self {
        Self {
            count: 0,
            modules: [KernelModule {
                image_base: 0,
                image_size: 0,
                path: [0; MODULE_PATH_BYTES],
            }; MAX_MODULES],
        }
    }
}

/// The exact byte length of [`KernelModuleList`].
pub const KERNEL_MODULE_LIST_BYTES: usize = core::mem::size_of::<KernelModuleList>();

/// Bytes reserved for one exported function's name, including the NUL.
pub const HOOK_NAME_BYTES: usize = 64;

/// How many exported functions one inline-hook answer carries.
pub const MAX_HOOKS: usize = 16;

/// How many prologue bytes are compared with the file on disk.
pub const PROLOGUE_BYTES: usize = 16;

/// One exported function's runtime prologue.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelHook {
    /// The export name, ASCII, NUL-terminated.
    pub name: [u8; HOOK_NAME_BYTES],
    /// Where the kernel says the function starts.
    pub address: u64,
    /// The first [`PROLOGUE_BYTES`] bytes at that address.
    pub prologue: [u8; PROLOGUE_BYTES],
}

/// The answer to [`crate::ioctl::IOCTL_INLINE_HOOKS`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelHookList {
    /// How many entries are filled.
    pub count: u32,
    /// The functions that were found.
    pub hooks: [KernelHook; MAX_HOOKS],
}

impl KernelHookList {
    /// A zeroed answer.
    pub const fn empty() -> Self {
        Self {
            count: 0,
            hooks: [KernelHook {
                name: [0; HOOK_NAME_BYTES],
                address: 0,
                prologue: [0; PROLOGUE_BYTES],
            }; MAX_HOOKS],
        }
    }
}

/// The exact byte length of [`KernelHookList`].
pub const KERNEL_HOOK_LIST_BYTES: usize = core::mem::size_of::<KernelHookList>();

/// The disk guard's counters, returned by
/// [`crate::ioctl::IOCTL_DISK_GUARD_STATS`].
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DiskGuardStats {
    /// Writes refused because they overlapped the first MiB.
    pub blocked: u64,
    /// Writes allowed because the writer was one of the disk tools.
    pub allowed: u64,
    /// 1 when the filter is attached, 0 when the guard did not install.
    pub installed: u32,
}
