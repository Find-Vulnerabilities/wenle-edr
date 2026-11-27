//! The hash allowlist: files the user has decided are trusted, by exact bytes.
//!
//! This is the user's statement of intent, not a claim about provenance. The
//! engine checks it before any rule, heuristic or model runs, so an allowed file
//! is not examined at all; the scan report says which digest did it, and this
//! command is where the digest is added or removed.
//!
//! One digest per line, with the path that produced it as a comment. That path
//! is for the person reading the file later; nothing depends on it, and a file
//! can be renamed after it is allowed because the digest is the identity.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use sha2::{Digest, Sha256};

use crate::cli::{AllowArgs, AllowCommand, Globals};
use crate::commands::Context;
use crate::exit::Exit;

/// Run an `allow` subcommand.
pub fn run(command: &AllowArgs, _globals: &Globals, context: &Context) -> Result<Exit> {
    let path = context.paths.db_dir.join("allowlist.txt");
    match &command.command {
        AllowCommand::Add { files } => add(&path, files)?,
        AllowCommand::List => list(&path)?,
        AllowCommand::Remove { targets } => remove(&path, targets)?,
    }
    Ok(Exit::Clean)
}

fn add(path: &PathBuf, files: &[PathBuf]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut existing = read(path);
    let mut appended = 0;
    for file in files {
        let bytes = std::fs::read(file)
            .with_context(|| format!("reading {} for its digest", file.display()))?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        if existing.iter().any(|(known, _)| known == &digest) {
            println!("already allowed  {digest}  {}", file.display());
            continue;
        }
        existing.push((digest.clone(), file.display().to_string()));
        appended += 1;
        println!("allowed          {digest}  {}", file.display());
    }
    if appended == 0 {
        return Ok(());
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    for (digest, display) in existing.iter().skip(existing.len() - appended) {
        writeln!(file, "{digest}  # {display}")?;
    }
    file.flush()?;
    println!("{appended} entr{} added to {}", if appended == 1 { "y" } else { "ies" }, path.display());
    Ok(())
}

fn list(path: &PathBuf) -> Result<()> {
    let entries = read(path);
    if entries.is_empty() {
        println!("the allowlist is empty ({})", path.display());
        return Ok(());
    }
    for (digest, comment) in entries {
        if comment.is_empty() {
            println!("{digest}");
        } else {
            println!("{digest}  {comment}");
        }
    }
    Ok(())
}

fn remove(path: &PathBuf, targets: &[String]) -> Result<()> {
    let mut entries = read(path);
    if entries.is_empty() {
        println!("the allowlist is empty; nothing to remove");
        return Ok(());
    }
    let mut wanted: Vec<String> = Vec::new();
    for target in targets {
        if target.len() == 64 && target.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            wanted.push(target.to_ascii_lowercase());
        } else {
            let candidate = std::path::Path::new(target);
            if candidate.is_file() {
                let bytes = std::fs::read(candidate)
                    .with_context(|| format!("reading {}", candidate.display()))?;
                wanted.push(format!("{:x}", Sha256::digest(&bytes)));
            } else {
                anyhow::bail!("{target} is neither a sha256 digest nor a file");
            }
        }
    }
    let before = entries.len();
    entries.retain(|(digest, _)| !wanted.contains(digest));
    let removed = before - entries.len();
    let mut text = String::new();
    for (digest, comment) in &entries {
        if comment.is_empty() {
            text.push_str(digest);
        } else {
            text.push_str(&format!("{digest}  # {comment}"));
        }
        text.push('\n');
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    println!("{removed} entr{} removed", if removed == 1 { "y" } else { "ies" });
    Ok(())
}

/// The digest and the free-text comment of every line that has a digest.
fn read(path: &PathBuf) -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let digest = line.get(..64)?.to_ascii_lowercase();
            if !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return None;
            }
            let comment = line[64..]
                .trim_start_matches(['#', ' '])
                .trim()
                .to_owned();
            Some((digest, comment))
        })
        .collect()
}
