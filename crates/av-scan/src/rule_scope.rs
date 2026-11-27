//! Which rules may speak about which kind of file.
//!
//! The rule language has no file-type condition. A rule that says "a PDF with
//! JavaScript that evaluates" is therefore evaluated against every byte the
//! engine reads, and on 2026-11-25 a full System32 scan convicted ten Microsoft
//! binaries because their bytes happen to contain the same short strings:
//! `urlmon.dll`, `wininet.dll`, `mshtml.dll`, `edgehtml.dll`, `iertutil.dll`,
//! `wldp.dll`, `Windows.Data.Pdf.dll`, `resources.pak`, `mscories.dll` and
//! `dssec.dat`. A PDF rule matching a browser DLL is not a detection; it is the
//! rule speaking outside its subject.
//!
//! This module gives the five document rules a subject. It is deliberately a
//! name table rather than a new rule-language feature: the rules that need it
//! are the ones this repository writes, and a table is visible in one place.
//! Renaming a rule means updating this table; the test at the bottom fails if a
//! mapped name disappears from the compiled database only in the sense that the
//! mapping is then dead code, so the table is kept beside the rules it names.

use std::path::Path;

/// The document a rule is allowed to speak about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Lnk,
    Pdf,
    Inf,
    Reg,
    Office,
    /// Everything else: the rule table does not restrict this file.
    Other,
}

/// Recognise the subject from the name and the first bytes.
///
/// Extension alone is not enough -- a dropper renamed to `.txt` should still be
/// read -- but a document rule needs the container's identity, and the identity
/// is either the extension the shell uses or the magic the format starts with.
pub fn of(path: &Path, data: &[u8]) -> Kind {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if extension == "lnk" || data.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00]) {
        return Kind::Lnk;
    }
    if extension == "pdf" || data.starts_with(b"%PDF-") {
        return Kind::Pdf;
    }
    if extension == "inf" || starts_with_text(data, b"[Version]") {
        return Kind::Inf;
    }
    if extension == "reg" || starts_with_text(data, b"Windows Registry Editor") {
        return Kind::Reg;
    }
    const OFFICE: &[&str] = &[
        "doc", "docm", "docx", "dot", "dotm", "xls", "xlsm", "xlsx", "xlt", "xltm", "ppt", "pptm",
        "pptx", "pot", "potm", "rtf", "msg", "one", "vsd", "vsdm", "pub",
    ];
    if OFFICE.contains(&extension.as_str())
        || data.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    {
        return Kind::Office;
    }
    Kind::Other
}

/// The rule's subject, when it has one.
fn subject(rule: &str) -> Option<Kind> {
    match rule {
        "dropper_lnk_shell" => Some(Kind::Lnk),
        "exploit_pdf_javascript" => Some(Kind::Pdf),
        "dropper_inf_execution" => Some(Kind::Inf),
        "dropper_reg_run_command" => Some(Kind::Reg),
        "macro_office_autostart_download" => Some(Kind::Office),
        _ => None,
    }
}

/// Whether a rule may report this file.
pub fn applies(rule: &str, kind: Kind) -> bool {
    match subject(rule) {
        None => true,
        Some(subject) => subject == kind,
    }
}

/// `[Version]` after a UTF-8 BOM, a UTF-16 BOM or leading whitespace.
fn starts_with_text(data: &[u8], needle: &[u8]) -> bool {
    let start = if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else if data.starts_with(&[0xFF, 0xFE]) || data.starts_with(&[0xFE, 0xFF]) {
        // UTF-16: compare the needle widened, not the raw bytes.
        let wide = data
            .get(2..)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|pair| pair[0])
            .collect::<Vec<_>>();
        return wide
            .iter()
            .skip_while(|byte| **byte == b' ' || **byte == b'\t' || **byte == b'\r' || **byte == b'\n')
            .copied()
            .collect::<Vec<_>>()
            .starts_with(needle);
    } else {
        0
    };
    data.get(start..)
        .unwrap_or_default()
        .iter()
        .skip_while(|byte| **byte == b' ' || **byte == b'\t' || **byte == b'\r' || **byte == b'\n')
        .copied()
        .collect::<Vec<_>>()
        .starts_with(needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pdf_rule_does_not_apply_to_a_dll() {
        let kind = of(Path::new(r"C:\Windows\System32\urlmon.dll"), b"MZ");
        assert_eq!(kind, Kind::Other);
        assert!(!applies("exploit_pdf_javascript", kind));
        assert!(applies("some_other_rule", kind));
    }

    #[test]
    fn the_document_kinds_are_recognised_by_magic_as_well_as_name() {
        assert_eq!(of(Path::new("x.bin"), b"%PDF-1.7"), Kind::Pdf);
        assert_eq!(of(Path::new("x.lnk"), b"anything"), Kind::Lnk);
        assert_eq!(of(Path::new("x.dat"), b"[Version]\r\n"), Kind::Inf);
        assert_eq!(of(Path::new("x.bin"), b"Windows Registry Editor Version 5.00"), Kind::Reg);
        assert_eq!(of(Path::new("x.docx"), b"PK"), Kind::Office);
        assert!(applies("exploit_pdf_javascript", Kind::Pdf));
        assert!(!applies("exploit_pdf_javascript", Kind::Lnk));
    }
}
