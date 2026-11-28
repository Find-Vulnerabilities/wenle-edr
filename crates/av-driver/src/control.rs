//! The control device the kernel audits will answer on.
//!
//! The minifilter's communication port is a one-way conversation about file
//! decisions: the driver publishes, the service answers, and there is no place
//! in that protocol for a question the service asks *the driver*. The three
//! kernel audits — inline hooks, hidden modules, raw-disk writes — are all
//! questions, so the driver exposes a device object and a small IOCTL surface.
//!
//! This file starts with the surface itself and one answer,
//! [`IOCTL_GET_VERSION`]. The audit IOCTLs are added on top; each one is a
//! fixed-size request/response with `METHOD_BUFFERED`, so the I/O manager does
//! the user-pointer validation and the driver never dereferences a user address.
//!
//! # Why a separate device and not an IOCTL on the filter
//!
//! A minifilter has no device object of its own to dispatch `IRP_MJ_DEVICE_CONTROL`;
//! the filter manager owns the volumes. Creating a control device is the
//! documented shape for a minifilter that also needs a control plane — see
//! Microsoft's "Creating the Control Device Object" — and it keeps the audit
//! surface out of the file path entirely.

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use windows_sys::Wdk::Foundation::{DEVICE_OBJECT, DRIVER_OBJECT, IO_STACK_LOCATION, IRP};
use windows_sys::Wdk::Storage::FileSystem::{DO_BUFFERED_IO, DO_DIRECT_IO};
use windows_sys::Wdk::System::SystemServices::{
    IoAttachDevice, IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice, IoDeleteSymbolicLink,
    IoDetachDevice, IofCallDriver, IofCompleteRequest,
    IoGetCurrentProcess, MmGetSystemRoutineAddress, PsGetCurrentProcessId, IRP_MJ_CLOSE,
    IRP_MJ_CREATE,
    IRP_MJ_DEVICE_CONTROL, IRP_MJ_WRITE,
};
use windows_sys::Win32::Foundation::UNICODE_STRING;
use windows_sys::Wdk::Storage::FileSystem::SeLocateProcessImageName;

/// `GENERIC_WRITE` and the file-write bits a raw disk handle can ask for.
const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_APPEND_DATA: u32 = 0x0000_0004;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;

/// `STATUS_SUCCESS`.
const STATUS_SUCCESS: i32 = 0;
/// `STATUS_INVALID_DEVICE_REQUEST`.
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
/// `FILE_DEVICE_UNKNOWN`.
const FILE_DEVICE_UNKNOWN: u32 = 0x22;

/// `SystemModuleInformation`, from `ntifs.h`/`ntddk.h`.
const SYSTEM_MODULE_INFORMATION: u32 = 11;
/// `STATUS_INFO_LENGTH_MISMATCH`.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004u32 as i32;
/// `STATUS_BUFFER_TOO_SMALL`.
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;
/// `POOL_FLAG_NON_PAGED`, from `wdm.h`.
const POOL_FLAG_NON_PAGED: u64 = 0x40;
/// The pool tag the module buffer is allocated under: `'WleM'`.
const MODULE_POOL_TAG: u32 = u32::from_le_bytes(*b"WleM");
/// `offset_of!(RTL_PROCESS_MODULES, Modules)` on x64: the count is a ULONG
/// followed by four bytes of alignment before the first entry.
const MODULES_OFFSET: usize = 8;
/// `sizeof(RTL_PROCESS_MODULE_INFORMATION)` on x64.
const MODULE_INFORMATION_SIZE: usize = 296;
/// `offset_of!(RTL_PROCESS_MODULE_INFORMATION, FullPathName)` on x64.
const MODULE_FULL_PATH_OFFSET: usize = 40;

extern "system" {
    /// The kernel's own module list. Linked from `ntoskrnl.lib` by `wdk-build`.
    fn ZwQuerySystemInformation(
        class: u32,
        buffer: *mut core::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
    fn ExAllocatePool2(flags: u64, bytes: usize, tag: u32) -> *mut core::ffi::c_void;
    fn ExFreePool(pointer: *mut core::ffi::c_void);
}

/// The device the audits are asked on. The backslashes are part of the name.
const DEVICE_NAME: &[u16] = &[
    '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
    '\\' as u16, 'W' as u16, 'e' as u16, 'n' as u16, 'l' as u16, 'e' as u16, 'A' as u16,
    'v' as u16, 'A' as u16, 'u' as u16, 'd' as u16, 'i' as u16, 't' as u16,
];

/// The name user mode opens: `\\.\WenleAvAudit`.
const LINK_NAME: &[u16] = &[
    '\\' as u16, 'D' as u16, 'o' as u16, 's' as u16, 'D' as u16, 'e' as u16, 'v' as u16,
    'i' as u16, 'c' as u16, 'e' as u16, 's' as u16, '\\' as u16, 'W' as u16, 'e' as u16,
    'n' as u16, 'l' as u16, 'e' as u16, 'A' as u16, 'v' as u16, 'A' as u16, 'u' as u16,
    'd' as u16, 'i' as u16, 't' as u16,
];

/// The device object, for teardown. Null until [`create`] succeeds.
static DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());

/// The disk upper filters and the devices they are attached to.
///
/// One filter is created per physical disk. `Harddisk0` alone left every other
/// disk, USB stick and VHD outside the guard.
const MAX_DISKS: usize = 32;
/// One physical disk can expose more than one `DRn` device. A USB stick is
/// commonly `\\Device\\Harddisk1\\DR1` while the system disk is `DR0`, which is
/// why attaching only `DR0` left every USB disk outside the guard.
const MAX_DR: usize = 4;
const MAX_FILTERS: usize = MAX_DISKS * MAX_DR;
static DISK_FILTERS: [AtomicPtr<DEVICE_OBJECT>; MAX_FILTERS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_FILTERS];
static DISK_ATTACHED: [AtomicPtr<DEVICE_OBJECT>; MAX_FILTERS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_FILTERS];

/// How many writes the guard has refused.
static BLOCKED_WRITES: AtomicU64 = AtomicU64::new(0);
/// How many writes the disk tools were allowed to make in the guarded range.
static ALLOWED_WRITES: AtomicU64 = AtomicU64::new(0);

/// Writers allowed to touch the first MiB, as path suffixes.
///
/// The suffix is checked against the full image path, so a copy of
/// `diskpart.exe` in `%TEMP%` is not allowed: it has to sit under
/// `\System32\`. These are the tools whose whole job is to write partition
/// and boot sectors; everything else is refused, which is the point.
const ALLOWED_WRITERS: [&str; 10] = [
    "\\system32\\diskpart.exe",
    "\\system32\\format.com",
    "\\system32\\bcdboot.exe",
    "\\system32\\bootrec.exe",
    "\\system32\\chkdsk.exe",
    "\\system32\\dism.exe",
    "\\system32\\mmc.exe",
    "\\system32\\cleanmgr.exe",
    "\\system32\\winsat.exe",
    "\\system32\\setup.exe",
];

/// The disk the guard protects and the filter device that protects it.
const DISK_DEVICE_NAME: &[u16] = &[
    '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
    '\\' as u16, 'W' as u16, 'e' as u16, 'n' as u16, 'l' as u16, 'e' as u16, 'A' as u16,
    'v' as u16, 'D' as u16, 'i' as u16, 's' as u16, 'k' as u16,
];
const DISK_TARGET_NAME: &[u16] = &[
    '\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16, 'e' as u16,
    '\\' as u16, 'H' as u16, 'a' as u16, 'r' as u16, 'd' as u16, 'd' as u16, 'i' as u16,
    's' as u16, 'k' as u16, '0' as u16, '\\' as u16, 'D' as u16, 'R' as u16, '0' as u16,
];

/// One response word for [`av_driver_proto::ioctl::IOCTL_GET_VERSION`].
const AUDIT_ABI_VERSION: u32 = 1;

/// Build a `UNICODE_STRING` over a UTF-16 slice.
///
/// `Length` is bytes and excludes the NUL; the slice is a `'static`, so the
/// pointer is valid for as long as the driver is loaded.
fn unicode(text: &'static [u16]) -> UNICODE_STRING {
    unicode_of(text)
}

/// The same over a slice that does not have to be static.
fn unicode_of(text: &[u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_ptr() as *mut u16,
    }
}

/// Create the control device and its symbolic link.
///
/// Returns the `NTSTATUS` from `IoCreateDevice`; the caller logs and continues.
/// A machine whose control device could not be created still has the minifilter,
/// which is the part that refuses executions.
///
/// # Safety
///
/// Called once from `DriverEntry`, at `PASSIVE_LEVEL`, with the driver object
/// the loader passed.
pub unsafe fn create(driver: *mut c_void) -> i32 {
    let driver = driver.cast::<DRIVER_OBJECT>();
    let mut device: *mut DEVICE_OBJECT = core::ptr::null_mut();
    let status = unsafe {
        IoCreateDevice(
            driver,
            0,
            &unicode(DEVICE_NAME),
            FILE_DEVICE_UNKNOWN,
            0,
            0,
            &mut device,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    // Buffered I/O: the I/O manager copies the request and the response between
    // user mode and the nonpaged system buffer, so this driver never touches a
    // user-mode pointer.
    unsafe {
        (*device).Flags |= DO_BUFFERED_IO;
        (*driver).MajorFunction[IRP_MJ_CREATE as usize] = Some(dispatch);
        (*driver).MajorFunction[IRP_MJ_CLOSE as usize] = Some(dispatch);
        (*driver).MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(dispatch);
    }
    let link = unsafe { IoCreateSymbolicLink(&unicode(LINK_NAME), &unicode(DEVICE_NAME)) };
    if link != STATUS_SUCCESS {
        // The device is still reachable by its `\Device\` name, which is what a
        // test uses; a missing `\DosDevices\` link only makes `\\.\` fail.
        return link;
    }
    DEVICE.store(device, Ordering::Release);
    STATUS_SUCCESS
}

/// The ntoskrnl exports whose prologues are compared with the file on disk.
///
/// A rootkit hooks the functions a security product calls, and these are the
/// calls a hiding rootkit has to intercept: file/directory information, value
/// keys, process and memory access, thread creation. The list is fixed and
/// small because the answer is a fixed-size buffer; a caller that wants more
/// can extend it with a new ABI version.
const HOOK_NAMES: [&[u16]; 10] = [
    &[
        'N' as u16, 't' as u16, 'C' as u16, 'r' as u16, 'e' as u16, 'a' as u16, 't' as u16,
        'e' as u16, 'F' as u16, 'i' as u16, 'l' as u16, 'e' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'Q' as u16, 'u' as u16, 'e' as u16, 'r' as u16, 'y' as u16,
        'S' as u16, 'y' as u16, 's' as u16, 't' as u16, 'e' as u16, 'm' as u16, 'I' as u16,
        'n' as u16, 'f' as u16, 'o' as u16, 'r' as u16, 'm' as u16, 'a' as u16, 't' as u16,
        'i' as u16, 'o' as u16, 'n' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'Q' as u16, 'u' as u16, 'e' as u16, 'r' as u16, 'y' as u16,
        'D' as u16, 'i' as u16, 'r' as u16, 'e' as u16, 'c' as u16, 't' as u16, 'o' as u16,
        'r' as u16, 'y' as u16, 'F' as u16, 'i' as u16, 'l' as u16, 'e' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'Q' as u16, 'u' as u16, 'e' as u16, 'r' as u16, 'y' as u16,
        'V' as u16, 'a' as u16, 'l' as u16, 'u' as u16, 'e' as u16, 'K' as u16, 'e' as u16,
        'y' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'O' as u16, 'p' as u16, 'e' as u16, 'n' as u16, 'P' as u16,
        'r' as u16, 'o' as u16, 'c' as u16, 'e' as u16, 's' as u16, 's' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'R' as u16, 'e' as u16, 'a' as u16, 'd' as u16, 'V' as u16,
        'i' as u16, 'r' as u16, 't' as u16, 'u' as u16, 'a' as u16, 'l' as u16, 'M' as u16,
        'e' as u16, 'm' as u16, 'o' as u16, 'r' as u16, 'y' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'W' as u16, 'r' as u16, 'i' as u16, 't' as u16, 'e' as u16,
        'V' as u16, 'i' as u16, 'r' as u16, 't' as u16, 'u' as u16, 'a' as u16, 'l' as u16,
        'M' as u16, 'e' as u16, 'm' as u16, 'o' as u16, 'r' as u16, 'y' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'C' as u16, 'r' as u16, 'e' as u16, 'a' as u16, 't' as u16,
        'e' as u16, 'T' as u16, 'h' as u16, 'r' as u16, 'e' as u16, 'a' as u16, 'd' as u16,
        'E' as u16, 'x' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'Q' as u16, 'u' as u16, 'e' as u16, 'r' as u16, 'y' as u16,
        'I' as u16, 'n' as u16, 'f' as u16, 'o' as u16, 'r' as u16, 'm' as u16, 'a' as u16,
        't' as u16, 'i' as u16, 'o' as u16, 'n' as u16, 'P' as u16, 'r' as u16, 'o' as u16,
        'c' as u16, 'e' as u16, 's' as u16, 's' as u16,
    ],
    &[
        'N' as u16, 't' as u16, 'S' as u16, 'e' as u16, 't' as u16, 'V' as u16, 'a' as u16,
        'l' as u16, 'u' as u16, 'e' as u16, 'K' as u16, 'e' as u16, 'y' as u16,
    ],
];

/// Copy the runtime prologues of [`HOOK_NAMES`] into `buffer`.
unsafe fn fill_hooks(buffer: *mut u8, capacity: usize) -> (i32, usize) {
    if capacity < av_driver_proto::audit::KERNEL_HOOK_LIST_BYTES {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    let list = buffer.cast::<av_driver_proto::audit::KernelHookList>();
    unsafe {
        (*list).count = 0;
    }
    let mut found = 0usize;
    for name in HOOK_NAMES {
        let unicode_name = UNICODE_STRING {
            Length: (name.len() * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_ptr() as *mut u16,
        };
        let address = unsafe { MmGetSystemRoutineAddress(&unicode_name) };
        if address.is_null() {
            continue;
        }
        let entry = unsafe { &mut (*list).hooks[found] };
        unsafe {
            core::ptr::write_bytes(entry.name.as_mut_ptr(), 0, av_driver_proto::audit::HOOK_NAME_BYTES);
            for (index, unit) in name.iter().take(av_driver_proto::audit::HOOK_NAME_BYTES - 1).enumerate() {
                entry.name[index] = *unit as u8;
            }
            entry.address = address as usize as u64;
            for index in 0..av_driver_proto::audit::PROLOGUE_BYTES {
                entry.prologue[index] =
                    core::ptr::read_unaligned(address.cast::<u8>().add(index));
            }
        }
        found += 1;
        unsafe {
            (*list).count = found as u32;
        }
        if found == av_driver_proto::audit::MAX_HOOKS {
            break;
        }
    }
    (STATUS_SUCCESS, av_driver_proto::audit::KERNEL_HOOK_LIST_BYTES)
}

/// Copy the kernel's loaded module list into `buffer`.
///
/// Returns the `NTSTATUS` and the number of bytes written. The buffer is the
/// I/O manager's system buffer for a `METHOD_BUFFERED` request, so writing into
/// it is what the caller receives.
unsafe fn fill_modules(buffer: *mut u8, capacity: usize) -> (i32, usize) {
    let mut needed = 0u32;
    let first = unsafe {
        ZwQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            core::ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if first != STATUS_INFO_LENGTH_MISMATCH || needed == 0 {
        return (first, 0);
    }
    // A little slack: modules can load between the sizing call and the fill.
    let size = needed as usize + 4096;
    let pool = unsafe { ExAllocatePool2(POOL_FLAG_NON_PAGED, size, MODULE_POOL_TAG) };
    if pool.is_null() {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    let mut returned = 0u32;
    let status = unsafe {
        ZwQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            pool,
            size as u32,
            &mut returned,
        )
    };
    if status != STATUS_SUCCESS {
        unsafe { ExFreePool(pool) };
        return (status, 0);
    }
    let count = unsafe { core::ptr::read_unaligned(pool.cast::<u32>()) } as usize;
    let module_array = unsafe { pool.cast::<u8>().add(MODULES_OFFSET) };
    let capacity_entries = (capacity.saturating_sub(MODULES_OFFSET))
        / av_driver_proto::audit::MODULE_PATH_BYTES.max(core::mem::size_of::<av_driver_proto::audit::KernelModule>());
    let limit = count
        .min(av_driver_proto::audit::MAX_MODULES)
        .min(capacity_entries);
    let list = buffer.cast::<av_driver_proto::audit::KernelModuleList>();
    unsafe {
        (*list).count = limit as u32;
    }
    for index in 0..limit {
        let source = unsafe {
            module_array.add(index * MODULE_INFORMATION_SIZE)
        };
        let image_base = unsafe { core::ptr::read_unaligned(source.add(16).cast::<u64>()) };
        let image_size = unsafe { core::ptr::read_unaligned(source.add(24).cast::<u32>()) };
        let path = unsafe { source.add(MODULE_FULL_PATH_OFFSET) };
        let destination = unsafe { (*list).modules[index].path.as_mut_ptr() };
        unsafe {
            (*list).modules[index].image_base = image_base;
            (*list).modules[index].image_size = image_size;
            core::ptr::write_bytes(destination, 0, av_driver_proto::audit::MODULE_PATH_BYTES);
            let mut byte = 0usize;
            while byte + 1 < av_driver_proto::audit::MODULE_PATH_BYTES {
                let value = core::ptr::read_unaligned(path.add(byte));
                if value == 0 {
                    break;
                }
                *destination.add(byte) = value;
                byte += 1;
            }
        }
    }
    unsafe { ExFreePool(pool) };
    (STATUS_SUCCESS, av_driver_proto::audit::KERNEL_MODULE_LIST_BYTES)
}

/// The one dispatch routine for create, close and device control.
///
/// # Safety
///
/// Called by the I/O manager with a valid `DEVICE_OBJECT` and `IRP` at
/// `PASSIVE_LEVEL` or `APC_LEVEL`.
unsafe extern "system" fn control_dispatch(irp: *mut IRP) -> i32 {
    let stack = unsafe { (*(*irp).Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation) };
    let major = stack.MajorFunction;
    if major != IRP_MJ_DEVICE_CONTROL as u8 {
        unsafe {
            (*irp).IoStatus.Anonymous.Status = STATUS_SUCCESS;
            (*irp).IoStatus.Information = 0;
            IofCompleteRequest(irp, 0);
        }
        return STATUS_SUCCESS;
    }
    // The offset is read explicitly rather than through the generated union:
    // on this x64 layout the I/O manager puts IoControlCode at +0x18 from the
    // stack location, while the generated `DeviceIoControl` arm reads +0x10 and
    // returned zero. The raw bytes were measured on the test VM, not guessed.
    let raw = &stack as *const _ as *const u8 as *const u32;
    let output_length = unsafe { core::ptr::read_unaligned(raw.add(2)) };
    let input_length = unsafe { core::ptr::read_unaligned(raw.add(4)) };
    let code = unsafe { core::ptr::read_unaligned(raw.add(6)) };
    let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer.cast::<u8>() };
    let mut information = 0usize;
    let mut status = STATUS_INVALID_DEVICE_REQUEST;
    if code == av_driver_proto::ioctl::IOCTL_GET_VERSION && output_length >= 4 && !buffer.is_null()
    {
        unsafe {
            core::ptr::write_unaligned(buffer.cast::<u32>(), AUDIT_ABI_VERSION);
        }
        information = 4;
        status = STATUS_SUCCESS;
    } else if code == av_driver_proto::ioctl::IOCTL_KERNEL_MODULES
        && output_length >= av_driver_proto::audit::KERNEL_MODULE_LIST_BYTES as u32
        && !buffer.is_null()
    {
        let (module_status, module_information) =
            unsafe { fill_modules(buffer, output_length as usize) };
        status = module_status;
        information = module_information;
    } else if code == av_driver_proto::ioctl::IOCTL_INLINE_HOOKS
        && output_length >= av_driver_proto::audit::KERNEL_HOOK_LIST_BYTES as u32
        && !buffer.is_null()
    {
        let (hook_status, hook_information) =
            unsafe { fill_hooks(buffer, output_length as usize) };
        status = hook_status;
        information = hook_information;
    } else if code == av_driver_proto::ioctl::IOCTL_DISK_GUARD_STATS
        && output_length >= core::mem::size_of::<av_driver_proto::audit::DiskGuardStats>() as u32
        && !buffer.is_null()
    {
        let stats = av_driver_proto::audit::DiskGuardStats {
            blocked: BLOCKED_WRITES.load(Ordering::Relaxed),
            allowed: ALLOWED_WRITES.load(Ordering::Relaxed),
            installed: if (0..MAX_FILTERS).any(|i| !DISK_FILTERS[i].load(Ordering::Acquire).is_null()) { 1 } else { 0 },
        };
        unsafe {
            core::ptr::write_unaligned(
                buffer.cast::<av_driver_proto::audit::DiskGuardStats>(),
                stats,
            );
        }
        information = core::mem::size_of::<av_driver_proto::audit::DiskGuardStats>();
        status = STATUS_SUCCESS;
    } else if code == av_driver_proto::ioctl::IOCTL_PROTECT_ORIGINAL {
        status = unsafe { crate::set_protected_original(buffer, input_length) };
    }
    unsafe {
        (*irp).IoStatus.Anonymous.Status = status;
        (*irp).IoStatus.Information = information;
        IofCompleteRequest(irp, 0);
    }
    status
}

/// Create the disk upper filter and attach it to the first physical disk.
///
/// Returns an `NTSTATUS`; a failure leaves the audit device working and no disk
/// guard, which is a machine that still has the file minifilter.
///
/// # Safety
///
/// Called once from `DriverEntry` at `PASSIVE_LEVEL`.
pub unsafe fn create_disk_guard(driver: *mut c_void) -> i32 {
    let driver = driver.cast::<DRIVER_OBJECT>();
    let mut installed = 0usize;
    let mut last_status = STATUS_SUCCESS;
    for index in 0..MAX_DISKS {
        for dr in 0..MAX_DR {
            let mut device_name = [0u16; 40];
            let mut target_name = [0u16; 40];
            let device_len = disk_name(index, dr, false, &mut device_name);
            let target_len = disk_name(index, dr, true, &mut target_name);
            let device_name = unicode_of(&device_name[..device_len]);
            let target_name = unicode_of(&target_name[..target_len]);
            let mut filter: *mut DEVICE_OBJECT = core::ptr::null_mut();
            let status = unsafe {
                IoCreateDevice(driver, 0, &device_name, 0x07, 0, 0, &mut filter)
            };
            if status != STATUS_SUCCESS {
                last_status = status;
                continue;
            }
            let mut attached: *mut DEVICE_OBJECT = core::ptr::null_mut();
            let attach = unsafe { IoAttachDevice(filter, &target_name, &mut attached) };
            if attach != STATUS_SUCCESS {
                // No HarddiskN\DRm on this machine; try the next instance.
                unsafe { IoDeleteDevice(filter) };
                last_status = attach;
                continue;
            }
            unsafe {
                (*filter).Flags |= (*attached).Flags & (DO_BUFFERED_IO | DO_DIRECT_IO);
            }
            let slot = index * MAX_DR + dr;
            DISK_FILTERS[slot].store(filter, Ordering::Release);
            DISK_ATTACHED[slot].store(attached, Ordering::Release);
            installed += 1;
        }
    }
    if installed == 0 { return last_status; }
    unsafe {
        for index in 0..28 { (*driver).MajorFunction[index] = Some(dispatch); }
    }
    STATUS_SUCCESS
}

/// Build `\Device\WenleAvDiskN` or `\Device\HarddiskN\DR0` into `out`.
fn disk_name(index: usize, dr: usize, target: bool, out: &mut [u16; 40]) -> usize {
    let prefix: &[u16] = if target {
        &['\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16,
          'e' as u16, '\\' as u16, 'H' as u16, 'a' as u16, 'r' as u16, 'd' as u16,
          'd' as u16, 'i' as u16, 's' as u16, 'k' as u16]
    } else {
        &['\\' as u16, 'D' as u16, 'e' as u16, 'v' as u16, 'i' as u16, 'c' as u16,
          'e' as u16, '\\' as u16, 'W' as u16, 'e' as u16, 'n' as u16, 'l' as u16,
          'e' as u16, 'A' as u16, 'v' as u16, 'D' as u16, 'i' as u16, 's' as u16,
          'k' as u16]
    };
    let mut at = 0usize;
    for unit in prefix { out[at] = *unit; at += 1; }
    at = push_digits(index, out, at);
    if target {
        for unit in ['\\' as u16, 'D' as u16, 'R' as u16] { out[at] = unit; at += 1; }
        at = push_digits(dr, out, at);
    } else {
        out[at] = '_' as u16; at += 1;
        at = push_digits(dr, out, at);
    }
    at
}

fn push_digits(value: usize, out: &mut [u16; 40], mut at: usize) -> usize {
    if value >= 10 { out[at] = b'0' as u16 + (value / 10) as u16; at += 1; }
    out[at] = b'0' as u16 + (value % 10) as u16;
    at + 1
}

/// The unified driver dispatch: control device by identity, everything else is
/// the disk filter and passes down except a write into the first MiB.
///
/// # Safety
///
/// Called by the I/O manager with a valid `DEVICE_OBJECT` and `IRP`.
unsafe extern "system" fn dispatch(device: *const DEVICE_OBJECT, irp: *mut IRP) -> i32 {
    if device == DEVICE.load(Ordering::Acquire) {
        return unsafe { control_dispatch(irp) };
    }
    for index in 0..MAX_FILTERS {
        if device == DISK_FILTERS[index].load(Ordering::Acquire) {
            let attached = DISK_ATTACHED[index].load(Ordering::Acquire);
            return unsafe { disk_dispatch(irp, attached) };
        }
    }
    unsafe {
        (*irp).IoStatus.Anonymous.Status = STATUS_INVALID_DEVICE_REQUEST;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, 0);
    }
    STATUS_INVALID_DEVICE_REQUEST
}

/// Pull `DesiredAccess` out of a create IRP's stack location.
///
/// The generated `Create` arm does not match this x64 layout, as with the
/// control request: the security context pointer is at stack+8 and
/// `DesiredAccess` is the second field of that structure.
unsafe fn create_desired_access(stack: *const IO_STACK_LOCATION) -> u32 {
    let raw = stack.cast::<u8>();
    let security = unsafe { core::ptr::read_unaligned(raw.add(8).cast::<*const u8>()) };
    if security.is_null() {
        return 0;
    }
    unsafe { core::ptr::read_unaligned(security.add(8).cast::<u32>()) }
}

/// Whether the current thread is the System process.
fn current_is_system() -> bool {
    // SAFETY: no arguments, valid at any IRQL.
    let pid = unsafe { PsGetCurrentProcessId() } as usize as u32;
    pid == 4
}

/// Whether this write's file object is the physical disk rather than a volume.
unsafe fn write_is_raw(stack: *const IO_STACK_LOCATION) -> bool {
    let file = unsafe { (*stack).FileObject };
    if file.is_null() {
        return false;
    }
    let device = unsafe { (*file).DeviceObject };
    if device.is_null() {
        return false;
    }
    (0..MAX_FILTERS).any(|index| {
        device == DISK_FILTERS[index].load(Ordering::Acquire)
            || device == DISK_ATTACHED[index].load(Ordering::Acquire)
    })
}

/// Whether the current process is one of [`ALLOWED_WRITERS`].
///
/// `SeLocateProcessImageName` returns a buffer the caller owns, so it is freed
/// here. A process whose image cannot be named is refused: the fallback must be
/// the safe one for a boot-sector write.
unsafe fn current_writer_allowed() -> bool {
    let mut image: *mut UNICODE_STRING = core::ptr::null_mut();
    let status = unsafe { SeLocateProcessImageName(IoGetCurrentProcess(), &mut image) };
    if status != STATUS_SUCCESS || image.is_null() {
        return false;
    }
    let named = unsafe { &*image };
    if named.Buffer.is_null() || named.Length == 0 {
        unsafe { ExFreePool(image.cast()) };
        return false;
    }
    let units = unsafe {
        core::slice::from_raw_parts(named.Buffer, (named.Length / 2) as usize)
    };
    let allowed = ALLOWED_WRITERS
        .iter()
        .any(|suffix| ends_with_ascii_ci(units, suffix));
    unsafe { ExFreePool(image.cast()) };
    allowed
}

/// Case-insensitive ASCII suffix test over UTF-16, without allocating.
fn ends_with_ascii_ci(path: &[u16], suffix: &str) -> bool {
    let suffix = suffix.as_bytes();
    if path.len() < suffix.len() {
        return false;
    }
    let start = path.len() - suffix.len();
    for (index, expected) in suffix.iter().enumerate() {
        let unit = path[start + index];
        if unit > 0x7f {
            return false;
        }
        let byte = (unit as u8).to_ascii_lowercase();
        if byte != *expected {
            return false;
        }
    }
    true
}

/// Pass every disk IRP down, except a write that overlaps the first MiB.
unsafe fn disk_dispatch(irp: *mut IRP, attached: *mut DEVICE_OBJECT) -> i32 {
    let current = unsafe { (*irp).Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation };
    let major = unsafe { (*current).MajorFunction };

    // A raw write has to open the physical disk for writing first. Refusing
    // that open is stricter than inspecting the first MiB of a write: a
    // rootkit cannot address sector 100 MiB if it never gets a write handle.
    // The volume's own opens come from System, and the disk tools are the same
    // allowlist the write gate uses.
    if major == IRP_MJ_WRITE as u8 {
        // Raw offsets, as with the control request: the generated Write arm
        // does not match the layout this x64 build actually uses.
        let raw = current.cast::<u8>();
        let length = unsafe { core::ptr::read_unaligned(raw.add(8).cast::<u32>()) };
        let offset = unsafe { core::ptr::read_unaligned(raw.add(16).cast::<i64>()) };
        // A raw handle's file object is attached to the physical disk, not to
        // a volume; a file write through NTFS is attached to the volume. This
        // catches a raw write at any sector, not only the first MiB, while
        // leaving ordinary file writes alone.
        let raw = unsafe { write_is_raw(current) };
        if length > 0 && (offset < 1_048_576 || raw) {
            if unsafe { current_writer_allowed() } {
                ALLOWED_WRITES.fetch_add(1, Ordering::Relaxed);
            } else {
                BLOCKED_WRITES.fetch_add(1, Ordering::Relaxed);
                unsafe {
                    (*irp).IoStatus.Anonymous.Status = 0xC000_0022u32 as i32; // ACCESS_DENIED
                    (*irp).IoStatus.Information = 0;
                    IofCompleteRequest(irp, 0);
                }
                return 0xC000_0022u32 as i32;
            }
        }
    }
    unsafe {
        (*irp).CurrentLocation += 1;
        (*irp).Tail.Overlay.Anonymous2.Anonymous.CurrentStackLocation = current.add(1);
        IofCallDriver(attached, irp)
    }
}

/// Detach and delete the disk filter, then remove the control device and link.
///
/// # Safety
///
/// Called once from the minifilter's unload callback at `PASSIVE_LEVEL`, after
/// the filter manager has stopped dispatching this driver's operations.
pub unsafe fn teardown() {
    for index in 0..MAX_FILTERS {
        let attached = DISK_ATTACHED[index].swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !attached.is_null() {
            unsafe { IoDetachDevice(attached) };
        }
        let filter = DISK_FILTERS[index].swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !filter.is_null() {
            unsafe { IoDeleteDevice(filter) };
        }
    }
    let device = DEVICE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !device.is_null() {
        unsafe { IoDeleteDevice(device) };
    }
    let _ = unsafe { IoDeleteSymbolicLink(&unicode(LINK_NAME)) };
}
