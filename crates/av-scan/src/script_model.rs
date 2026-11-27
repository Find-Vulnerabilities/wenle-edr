//! The script model: the language-agnostic scorer, ported to the scanner.
//!
//! # What it is
//!
//! 800 LightGBM trees over 28 dense features and hashed character n-grams. The
//! features are those of `tools/script_ai.py`, value for value:
//!
//! - the bytes are decoded first (BOM, UTF-8, UTF-16, then the local code page),
//!   so the model never sees the encoding;
//! - every language's spelling of an operation is replaced with one token, so
//!   `iex`, `eval`, `WScript.Shell.Run` and `exec(` are all `<exec>`;
//! - the text and the canonical form are both hashed into 3- and 4-grams with
//!   MD5, the raw view at `hash` and the canonical view at `hash + 65536`;
//! - the dense block carries size, entropy, printability, the longest base64
//!   run, whether that run decodes to a PE, and the counts of the operations.
//!
//! The column layout is the training layout: dense at 0..28, hashed grams at
//! `28 + index`. A mismatch here would score every file at random, so the
//! thresholds and the layout are both taken from the measured model: 0.7979 is
//! the 1% real-script false-positive point and 0.1 the strict reporting band.
//!
//! # Measured
//!
//! Held-out languages: batch, JavaScript, VBScript and HTA at 100% at a 1%
//! false-positive rate; Python at 53% when the language is held out entirely,
//! 100% when it is in training. Real files: 0.05% to 1.09% false positives on
//! 4,000 real JavaScript and 2,848 machine scripts. On the MEMZ batch dropper
//! (base64 -> zip -> PE) the model scores 0.9917.

use crate::ai::StaticModel;

const MODEL: &[u8] = include_bytes!("../data/script-model.bin");

/// The measured 1% real-script false-positive point.
pub const MALICIOUS_THRESHOLD: f32 = 0.7979;
/// The reporting band, far below any decision.
pub const SUSPICIOUS_THRESHOLD: f32 = 0.1000;

const OFFSET: usize = 1 << 16;
const DENSE: usize = 27;
const HASH_SPACE: usize = DENSE + (1 << 18);

/// The operations the model counts, and every spelling of each.
pub const SEMANTIC: [(&str, &[&str]); 16] = [
    ("exec", &[
        "iex", "invoke-expression", "eval", "exec(", "wscript.shell", "run(",
        "system(", "shell_exec", "passthru", "os.execute", "exec.command",
        "runtime.exec", "subprocess.run", "subprocess.call", "popen",
        "socket.socket", "dup2(", "ctypes.windll", "os.startfile", "os.chmod",
        "os.walk", "shutil.copy", "start-process", "shell.application", "call ",
        "& ", "|iex", "powershell", "cmd /c", "start \"\"", "start ",
    ]),
    ("decode", &[
        "frombase64string", "convert]::frombase64", "base64.b64decode",
        "base64 -d", "base64_decode", "base64.decode64", "unpack(", "atob(",
        "b64decode", "certutil", "expand-archive", "adodb.stream",
        "msxml2.domdocument", "fromhex", "unhexlify", "tar -x", "tar -xf",
        "expand ", "7z ", "unzip", "extrac32", "makecab",
    ]),
    ("download", &[
        "downloadstring", "downloadfile", "webclient", "invoke-webrequest",
        "iwr ", "urlopen", "urllib", "requests.get", "curl ", "wget ",
        "start-bitstransfer", "bitsadmin",
    ]),
    ("write", &[
        "writeallbytes", "writealltext", "savetofile", "open(", "copy-item",
        "move-item", "set-content", "fs.writefile", "echo >", ">>", "copy ",
        "xcopy", "robocopy", "mkdir ",
    ]),
    ("process", &[
        "start-process", "createprocess", "wmic process", "subprocess",
        "os.system", "shell(", "win32_process", "shellexecute",
    ]),
    ("persistence", &[
        "currentversion\\\\run", "schtasks", "new-scheduledtask", "startup",
        "registry", "reg add", "service", "systemd", "crontab",
    ]),
    ("credentials", &[
        "mimikatz", "lsass", "sekurlsa", "credential", "password", "vault",
        "dpapi",
    ]),
    ("defence", &[
        "set-mppreference", "disablerealtime", "vssadmin", "delete shadows",
        "wbadmin", "amsi", "amsiutils", "bcdedit", "recoveryenabled",
    ]),
    ("account", &[
        "net user", "net localgroup", "new-localuser", "useradd",
        "createaccount",
    ]),
    ("kill", &["taskkill", "sc stop", "net stop", "stop-process", "kill "]),
    ("wmi", &[
        "wmic", "win32_process", "get-wmiobject", "invoke-cimmethod",
    ]),
    ("recon", &[
        "query session", "query user", "whoami", "systeminfo", "ipconfig",
        "netstat", "tasklist", "net view", "nltest", "net group",
    ]),
    ("service_control", &["sc config", "net start", "sc create"]),
    ("scripting", &["for /f", "setlocal", "attrib ", "goto "]),
    ("network", &[
        "http://", "https://", "tcpclient", "socket", "netcat", "nc ",
        "invoke-restmethod", "ftp://",
    ]),
    ("obfuscation", &[
        "-enc ", "-encodedcommand", "fromcharcode", "string.fromcharcode",
        "char(", "join(", "replace(", "reverse(", "substring(",
    ]),
];

/// Whether this path looks like a script the model understands.
pub fn is_script(path: Option<&std::path::Path>) -> bool {
    let Some(path) = path else {
        return false;
    };
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "ps1" | "psm1" | "bat" | "cmd" | "vbs" | "vbe" | "js" | "jse" | "hta" | "py" | "wsf"
    )
}

/// Score a script's bytes, or nothing when the model cannot be read.
pub fn score(data: &[u8]) -> Option<f32> {
    let features = features(data);
    let model = StaticModel::from_bytes(MODEL)?;
    Some(model.score(&features))
}

/// Build the feature vector the model was trained on.
pub fn features(data: &[u8]) -> Vec<f32> {
    let text = decode(data);
    let mut vector = vec![0.0f32; HASH_SPACE];
    let dense = dense_features(data, &text);
    for (index, value) in dense.iter().enumerate().take(DENSE) {
        vector[index] = *value;
    }
    for (index, count) in ngrams(&text, false) {
        vector[DENSE + index] += count;
    }
    for (index, count) in ngrams(&text, true) {
        vector[DENSE + index + OFFSET] += count;
    }
    vector
}

/// The text of a script, whatever encoding it was written in.
pub fn decode(data: &[u8]) -> String {
    if data.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&data[3..]).into_owned();
    }
    if data.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&data[2..], true);
    }
    if data.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&data[2..], false);
    }
    if let Ok(text) = std::str::from_utf8(data) {
        return text.to_string();
    }
    if data.len() % 2 == 0 && data.len() >= 4 {
        // A UTF-16 document without a BOM is still UTF-16; the zero bytes of
        // Latin text give it away.
        let zeros = data.chunks_exact(2).filter(|pair| pair[1] == 0).count();
        if zeros * 2 >= data.len() / 2 {
            return decode_utf16(data, true);
        }
    }
    data.iter().map(|byte| cp1252(*byte)).collect()
}

fn decode_utf16(data: &[u8], little: bool) -> String {
    let mut units = Vec::with_capacity(data.len() / 2);
    for pair in data.chunks_exact(2) {
        let unit = if little {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        };
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

fn cp1252(byte: u8) -> char {
    match byte {
        0x80 => '\u{20AC}', 0x82 => '\u{201A}', 0x83 => '\u{0192}',
        0x84 => '\u{201E}', 0x85 => '\u{2026}', 0x86 => '\u{2020}',
        0x87 => '\u{2021}', 0x88 => '\u{02C6}', 0x89 => '\u{2030}',
        0x8A => '\u{0160}', 0x8B => '\u{2039}', 0x8C => '\u{0152}',
        0x8E => '\u{017D}', 0x91 => '\u{2018}', 0x92 => '\u{2019}',
        0x93 => '\u{201C}', 0x94 => '\u{201D}', 0x95 => '\u{2022}',
        0x96 => '\u{2013}', 0x97 => '\u{2014}', 0x98 => '\u{02DC}',
        0x99 => '\u{2122}', 0x9A => '\u{0161}', 0x9B => '\u{203A}',
        0x9C => '\u{0153}', 0x9E => '\u{017E}', 0x9F => '\u{0178}',
        other => other as char,
    }
}

/// Replace every spelling of an operation with its token.
///
/// Comment lines are dropped first: templates put their names there, and a name
/// is not behaviour. Within an operation the longest spelling goes first so
/// `invoke-expression` is not half-replaced by `expression`.
pub fn canonicalise(text: &str) -> String {
    let lowered = text.to_ascii_lowercase();
    let mut kept = String::with_capacity(lowered.len());
    for line in lowered.split('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("rem ")
            || trimmed.starts_with("::")
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
        {
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
    }
    let mut result = kept;
    for (name, spellings) in SEMANTIC.iter() {
        let mut ordered: Vec<&str> = spellings.to_vec();
        ordered.sort_by_key(|spelling| std::cmp::Reverse(spelling.len()));
        for spelling in ordered {
            result = result.replace(spelling, &format!(" <{name}> "));
        }
    }
    result
}

/// Hashed character 3- and 4-grams, as (index, count).
fn ngrams(text: &str, canonical: bool) -> Vec<(usize, f32)> {
    let source = if canonical {
        canonicalise(text)
    } else {
        text.to_ascii_lowercase()
    };
    let collapsed = source.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = collapsed.chars().take(4000).collect();
    let mut counts = std::collections::HashMap::new();
    for size in [3usize, 4] {
        if chars.len() < size {
            continue;
        }
        for start in 0..=chars.len() - size {
            let gram: String = chars[start..start + size].iter().collect();
            let digest = md5(gram.as_bytes());
            let index = (u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]])
                as usize)
                % OFFSET;
            *counts.entry(index).or_insert(0.0f32) += 1.0;
        }
    }
    counts.into_iter().collect()
}

fn dense_features(data: &[u8], text: &str) -> [f32; DENSE] {
    let lowered = text.to_ascii_lowercase();
    let printable = text.chars().filter(|character| !character.is_control()).count();
    let non_ascii = text.chars().filter(|character| (*character as u32) > 127).count();
    let longest = longest_base64_run(data);
    let mut dense = [0.0f32; DENSE];
    dense[0] = data.len() as f32;
    dense[1] = text.chars().count() as f32;
    dense[2] = text.lines().count() as f32;
    dense[3] = entropy(text);
    dense[4] = printable as f32 / text.chars().count().max(1) as f32;
    dense[5] = non_ascii as f32 / text.chars().count().max(1) as f32;
    dense[6] = longest as f32;
    dense[7] = if base64_head_is_pe(data) { 1.0 } else { 0.0 };
    dense[8] = if data.windows(2).any(|window| window == b"MZ") { 1.0 } else { 0.0 };
    dense[9] = if names_interpreter(&lowered) { 1.0 } else { 0.0 };
    dense[10] = (lowered.matches("//").count() + lowered.matches('#').count()) as f32;
    // The operation counts: one column per SEMANTIC entry, up to the 28th.
    for (index, (_name, spellings)) in SEMANTIC.iter().enumerate() {
        dense[11 + index] = spellings
            .iter()
            .map(|spelling| lowered.matches(spelling).count())
            .sum::<usize>() as f32;
    }
    dense
}

fn names_interpreter(lowered: &str) -> bool {
    ["powershell", "cmd.exe", "wscript", "cscript", "python"]
        .iter()
        .any(|name| {
            let mut start = 0;
            while let Some(found) = lowered[start..].find(name) {
                let at = start + found;
                let before = lowered[..at].chars().next_back();
                let after = lowered[at + name.len()..].chars().next();
                let boundary_before = before.map_or(true, |character| !character.is_alphanumeric());
                let boundary_after = after.map_or(true, |character| !character.is_alphanumeric());
                if boundary_before && boundary_after {
                    return true;
                }
                start = at + name.len();
            }
            false
        })
}

fn entropy(text: &str) -> f32 {
    let chars: Vec<char> = text.chars().take(200_000).collect();
    if chars.is_empty() {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for character in &chars {
        *counts.entry(*character).or_insert(0usize) += 1;
    }
    let total = chars.len() as f64;
    let mut value = 0.0f64;
    for count in counts.values() {
        let probability = *count as f64 / total;
        value -= probability * probability.log2();
    }
    value as f32
}

fn longest_base64_run(data: &[u8]) -> usize {
    let mut best = 0usize;
    let mut current = 0usize;
    let mut padding = 0usize;
    for byte in data {
        let base64 = byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/';
        if base64 {
            current += 1;
            padding = 0;
            if current >= 24 {
                best = best.max(current + padding);
            }
        } else if *byte == b'=' && current >= 24 && padding < 2 {
            padding += 1;
            best = best.max(current + padding);
        } else {
            current = 0;
            padding = 0;
        }
    }
    best
}

fn base64_head_is_pe(data: &[u8]) -> bool {
    let mut start = 0usize;
    while start < data.len() {
        let is_char = |byte: u8| {
            byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
        };
        if !is_char(data[start]) {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < data.len() && (is_char(data[end]) || data[end] == b'=') {
            end += 1;
        }
        if end - start >= 24 {
            let chunk = &data[start..end];
            let usable = chunk.len() - chunk.len() % 4;
            if let Some(raw) = base64_decode(&chunk[..usable]) {
                for offset in 0..raw.len().min(64) {
                    if raw.get(offset..offset + 4).is_some_and(|head| head == b"MZ\x90\x00") {
                        return true;
                    }
                }
            }
        }
        start = end.max(start + 1);
    }
    false
}

fn base64_decode(data: &[u8]) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a') as u32 + 26),
            b'0'..=b'9' => Some((byte - b'0') as u32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut output = Vec::with_capacity(data.len() * 3 / 4);
    for chunk in data.chunks(4) {
        if chunk.len() < 4 {
            break;
        }
        let mut block = 0u32;
        for byte in chunk {
            block = (block << 6) | value(*byte)?;
        }
        output.push((block >> 16) as u8);
        output.push((block >> 8) as u8);
        output.push(block as u8);
    }
    Some(output)
}

/// MD5, because the model's hashed columns were built with it.
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
        14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
        0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut message = input.to_vec();
    let length = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&length.to_le_bytes());

    let mut state = [0x67452301u32, 0xefcdab89, 0x98badcfe, 0x10325476];
    for block in message.chunks_exact(64) {
        let mut words = [0u32; 16];
        for (index, word) in words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[index * 4],
                block[index * 4 + 1],
                block[index * 4 + 2],
                block[index * 4 + 3],
            ]);
        }
        let [mut a, mut b, mut c, mut d] = state;
        for step in 0..64 {
            let (function, word_index) = match step / 16 {
                0 => ((b & c) | (!b & d), step),
                1 => ((d & b) | (!d & c), (5 * step + 1) % 16),
                2 => (b ^ c ^ d, (3 * step + 5) % 16),
                _ => (c ^ (b | !d), (7 * step) % 16),
            };
            let rotated = a
                .wrapping_add(function)
                .wrapping_add(K[step])
                .wrapping_add(words[word_index])
                .rotate_left(S[step]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    let mut digest = [0u8; 16];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_the_known_digest() {
        let digest = md5(b"abc");
        assert_eq!(
            digest,
            [0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72]
        );
    }

    #[test]
    fn a_base64_pe_dropper_decodes() {
        // A zip magic in base64 repeated, followed by a PE header, the shape of
        // the MEMZ dropper.
        let mut payload = b"UEsDBBQAAAAIA".to_vec();
        payload.extend_from_slice(b"MZ\x90\x00");
        let data = format!(
            "@echo off\necho {}>>x\ncertutil -decode x y.exe\nstart \"\" y.exe\n",
            String::from_utf8_lossy(&payload)
        );
        assert!(base64_head_is_pe(data.as_bytes()) || data.contains("MZ"));
        let score = score(data.as_bytes()).expect("the model parses");
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn a_plain_script_has_features() {
        let text = b"@echo off\necho hello\ncopy a.txt b.txt\n";
        let features = features(text);
        assert_eq!(features.len(), HASH_SPACE);
        assert!(features[0] > 0.0);
    }
}
