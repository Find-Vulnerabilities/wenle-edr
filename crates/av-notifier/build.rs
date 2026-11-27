//! Embed the product's icon in `wenle-notify.exe`.
//!
//! The startup list in Windows Settings shows the icon of the executable a
//! `Run` value names. The notifier is the executable the product registers, and
//! until this script existed it carried no `RT_GROUP_ICON`, so Wenle appeared in
//! that list with the generic blank icon while Surfshark and Defender showed
//! theirs.
//!
//! `rc.exe` from the Windows SDK is used rather than a build-dependency crate:
//! the SDK is already required to build the driver in this repository, the
//! resource is one line, and a crate that shells out to `rc.exe` would be the
//! same code with a version to pin.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../av-service/assets/wenle.ico");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let icon = manifest.join("../av-service/assets/wenle.ico");
    if !icon.is_file() {
        println!("cargo:warning=the product icon was not found at {}", icon.display());
        return;
    }
    let Some(rc) = find_rc() else {
        println!("cargo:warning=rc.exe was not found; the notifier will have no icon");
        return;
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("out dir"));
    let script = out.join("wenle-notify.rc");
    let resource = out.join("wenle-notify.res");
    // The icon alone fixed the bitmap but not the name: Windows' Startup
    // page labels a Run value by the executable's FileDescription and fell
    // back to "wenle-notify.exe" when there was none. The version block also
    // gives the shell the 48 px group it asks for; the old ICO's 48 px entry
    // was malformed and GDI+ threw while decoding it.
    // RC treats backslashes as escapes inside a quoted filename. The path
    // contains `\av-service`, and `\a` was eaten, so rc.exe reported "file
    // not found" and the link carried neither the icon nor the version block.
    let icon_rc = icon.display().to_string().replace('\\', "/");
    let source = format!(
        r#"1 ICON "{icon}"
1 VERSIONINFO
FILEVERSION 1,0,8,0
PRODUCTVERSION 1,0,8,0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Wenle"
      VALUE "FileDescription", "Wenle AV"
      VALUE "FileVersion", "1.0.0.0"
      VALUE "InternalName", "wenle-notify"
      VALUE "OriginalFilename", "wenle-notify.exe"
      VALUE "ProductName", "Wenle AV"
      VALUE "ProductVersion", "1.0.0.0"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        icon = icon_rc
    );
    if std::fs::write(&script, source).is_err() {
        println!("cargo:warning=the icon script could not be written");
        return;
    }
    let status = Command::new(&rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(&resource)
        .arg(&script)
        .status();
    match status {
        Ok(status) if status.success() && resource.is_file() => {
            // `link.exe` accepts a compiled resource file as an input. rustc
            // passes link arguments through for a binary target.
            println!("cargo:rustc-link-arg={}", resource.display());
        }
        Ok(status) => println!("cargo:warning=rc.exe failed with {status}"),
        Err(error) => println!("cargo:warning=rc.exe could not run: {error}"),
    }
}

/// The newest x64 `rc.exe` in the Windows Kits installation.
fn find_rc() -> Option<PathBuf> {
    let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(kits)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("x64").join("rc.exe").is_file())
        .collect();
    versions.sort();
    versions.pop().map(|version| version.join("x64").join("rc.exe"))
}
