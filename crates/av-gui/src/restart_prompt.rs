//! The one dialog whose action is a restart.
//!
//! A quarantine whose original file could not be deleted is the one state a
//! notification card cannot carry honestly. The bytes are in the vault, but the
//! file the user can still open is the file that matters, and a toast has no
//! buttons here (see `notify.rs`: a toast button needs a COM activator this
//! product does not register). So this is a native `TaskDialogIndirect`, posted
//! from a worker thread after the vault reports `original_removed == false`.
//!
//! The dialog says what is true, not what would be reassuring: the threat is
//! still on this computer. Restart is the only action it offers because it is
//! the only action that reliably ends the handle keeping the file alive. The
//! close button is allowed; a user who dismisses it keeps the warning in the
//! window's quarantine list and in the log, and the removal retry stays queued.

#[cfg(windows)]
pub fn show(file_name: &str) {
    let file_name = file_name.to_owned();
    std::thread::Builder::new()
        .name("wenle-restart-prompt".to_string())
        .spawn(move || show_blocking(&file_name))
        .ok();
}

#[cfg(not(windows))]
pub fn show(_file_name: &str) {}

#[cfg(windows)]
fn show_blocking(file_name: &str) {
    use windows::core::{s, w, BOOL, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{HINSTANCE, HWND};
    use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows::Win32::UI::Controls::{
        TASKDIALOGCONFIG, TASKDIALOG_BUTTON, TDF_ALLOW_DIALOG_CANCELLATION,
    };

    type TaskDialogIndirectFn = unsafe extern "system" fn(
        *const TASKDIALOGCONFIG,
        *mut i32,
        *mut i32,
        *mut BOOL,
    ) -> HRESULT;

    // Resolved dynamically on purpose. A static import of `TaskDialogIndirect`
    // makes the whole GUI fail to start with "entry point not found" on a
    // process whose comctl32 is v5; that is the failure measured on the host
    // after the first build, and it takes the window with it. comctl32 v6 is
    // loaded when present, and a missing export degrades to no dialog rather
    // than to no GUI.
    let module = match unsafe { LoadLibraryW(w!("comctl32.dll")) } {
        Ok(module) => module,
        Err(error) => {
            log::warn!("comctl32 could not be loaded for the restart prompt: {error}");
            return;
        }
    };
    let Some(proc) = (unsafe { GetProcAddress(module, s!("TaskDialogIndirect")) }) else {
        log::warn!("comctl32 has no TaskDialogIndirect export; the restart prompt is unavailable");
        return;
    };
    // SAFETY: the export is the documented `TaskDialogIndirect` entry point,
    // and its signature is the one declared above from commctrl.h.
    let task_dialog: TaskDialogIndirectFn = unsafe { std::mem::transmute(proc) };

    const RESTART_BUTTON: i32 = 100;

    let file_name: Vec<u16> = file_name.encode_utf16().chain(std::iter::once(0)).collect();
    let content = format!(
        "'{}' is still on this computer because a program has it open. Restart to remove it.",
        file_name_to_display(file_name.as_slice())
    );
    let content: Vec<u16> = content.encode_utf16().chain(std::iter::once(0)).collect();

    let buttons = [TASKDIALOG_BUTTON {
        nButtonID: RESTART_BUTTON,
        pszButtonText: w!("Restart"),
    }];

    let config = TASKDIALOGCONFIG {
        cbSize: std::mem::size_of::<TASKDIALOGCONFIG>() as u32,
        hwndParent: HWND::default(),
        hInstance: HINSTANCE::default(),
        dwFlags: TDF_ALLOW_DIALOG_CANCELLATION,
        pszWindowTitle: w!("Wenle Antivirus"),
        pszMainInstruction: w!("The threat is still on this computer."),
        pszContent: PCWSTR(content.as_ptr()),
        cButtons: buttons.len() as u32,
        pButtons: buttons.as_ptr(),
        nDefaultButton: RESTART_BUTTON,
        ..Default::default()
    };

    let mut clicked = 0i32;
    // SAFETY: every pointer in `config` points at a NUL-terminated buffer or
    // at `buttons`, both of which outlive the call. The dialog owns no handle
    // we keep, and a failure is reported by the HRESULT rather than by a
    // partially-filled out-parameter.
    let result = unsafe { task_dialog(&config, &mut clicked, std::ptr::null_mut(), std::ptr::null_mut()) };
    if result.is_err() {
        log::warn!("the restart-required task dialog could not be shown: {result:?}");
        return;
    }
    if clicked == RESTART_BUTTON {
        log::warn!(
            "the user chose Restart because {} is still on disk",
            file_name_to_display(file_name.as_slice())
        );
        match std::process::Command::new("shutdown.exe")
            .args(["/r", "/t", "0"])
            .spawn()
        {
            Ok(_) => {}
            Err(error) => log::error!("the restart command could not be started: {error}"),
        }
    }
}

/// Rebuild the display name from the UTF-16 buffer without rescanning the
/// original `String`, which was moved into the dialog's content above.
#[cfg(windows)]
fn file_name_to_display(buffer: &[u16]) -> String {
    let end = buffer.iter().position(|unit| *unit == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}
