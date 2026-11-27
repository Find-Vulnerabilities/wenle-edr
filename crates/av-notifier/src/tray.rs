//! The notifier's icon in the Windows notification area.
//!
//! The notifier is the process started at sign-in, so it is the one that has
//! to put Wenle in the tray. `Shell_NotifyIconW` needs a window to receive its
//! callbacks, so the icon gets a message-only window on a thread of its own:
//! never drawn, never in the taskbar, just a handle the shell can post to.
//!
//! Left or right click opens the window. The icon is a way back to the
//! product, not a second settings surface.

#![cfg(windows)]

use std::sync::mpsc::{self, Sender};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, ShellExecuteW, NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_TIP, NIM_ADD,
    NIM_SETVERSION, NOTIFYICONDATAW, NOTIFYICON_VERSION_4, NIN_SELECT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, LoadIconW,
    RegisterClassW, TranslateMessage, HWND_MESSAGE, SW_SHOWNORMAL, WM_APP, WM_LBUTTONUP,
    WM_RBUTTONUP, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};

const TRAY_ID: u32 = 1;
const CALLBACK: u32 = WM_APP + 1;
const START_TIMEOUT: Duration = Duration::from_secs(5);

static STARTED: OnceLock<bool> = OnceLock::new();

/// Put the icon in the notification area.
///
/// `true` means the shell accepted it. The thread keeps running for the life
/// of the process.
pub fn start() -> bool {
    *STARTED.get_or_init(|| {
        let (ready, answer) = mpsc::channel();
        let spawned = thread::Builder::new()
            .name("wenle-tray".to_owned())
            .spawn(move || unsafe { install_and_loop(ready) });
        match spawned {
            Ok(_) => answer.recv_timeout(START_TIMEOUT).unwrap_or(false),
            Err(_) => false,
        }
    })
}

unsafe fn install_and_loop(ready: Sender<bool>) {
    let instance = unsafe { GetModuleHandleW(None) }.unwrap_or_default();
    let class_name = w!("WenleNotifierTray");
    let window_class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance.into(),
        lpszClassName: class_name,
        ..unsafe { std::mem::zeroed() }
    };
    if unsafe { RegisterClassW(&window_class) } == 0 {
        let _ = ready.send(false);
        return;
    }
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            class_name,
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance.into()),
            None,
        )
    };
    let Ok(hwnd) = hwnd else {
        let _ = ready.send(false);
        return;
    };
    let icon = unsafe { LoadIconW(Some(instance.into()), PCWSTR(1 as *const u16)) };
    let icon = match icon {
        Ok(icon) => icon,
        Err(_) => unsafe { LoadIconW(None, PCWSTR(32512 as *const u16)) }.unwrap_or_default(),
    };
    let mut data = unsafe { std::mem::zeroed::<NOTIFYICONDATAW>() };
    data.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    data.hWnd = hwnd;
    data.uID = TRAY_ID;
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    data.uCallbackMessage = CALLBACK;
    data.hIcon = icon;
    let tip: Vec<u16> = "Wenle AV".encode_utf16().chain(Some(0)).collect();
    let copy = tip.len().min(data.szTip.len());
    data.szTip[..copy].copy_from_slice(&tip[..copy]);
    if !unsafe { Shell_NotifyIconW(NIM_ADD, &data) }.as_bool() {
        let _ = ready.send(false);
        unsafe { DestroyWindow(hwnd) }.ok();
        return;
    }
    data.Anonymous.uVersion = NOTIFYICON_VERSION_4;
    unsafe { Shell_NotifyIconW(NIM_SETVERSION, &data) };
    let _ = ready.send(true);

    let mut message = unsafe { std::mem::zeroed() };
    while unsafe { GetMessageW(&mut message, None, 0, 0) }.0 > 0 {
        unsafe {
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == CALLBACK {
        let event = lparam.0 as u32;
        if event == WM_LBUTTONUP || event == WM_RBUTTONUP || event == NIN_SELECT {
            open_window();
        }
        return LRESULT(0);
    }
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn open_window() {
    let exe = std::env::current_exe().ok();
    let gui = exe
        .as_ref()
        .and_then(|path| path.parent())
        .map(|dir| dir.join("wenle-gui.exe"));
    let Some(gui) = gui.filter(|path| path.is_file()) else {
        return;
    };
    let file: Vec<u16> = gui.to_string_lossy().encode_utf16().chain(Some(0)).collect();
    unsafe {
        ShellExecuteW(
            None,
            w!("open"),
            PCWSTR(file.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }
}
