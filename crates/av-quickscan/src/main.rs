//! `wenle-scan` — scan one path, including the members of an archive, without
//! the service and without being `wenle.exe`.
//!
//! # Why this is a separate program
//!
//! The driver strips process rights from handles to the product's own images and
//! recognises them by image name. A second program called `wenle.exe` is
//! therefore treated as the product, and a parent running without elevation that
//! waits on it can wait for ever -- measured on the host on 2026-11-08. This
//! binary is `wenle-scan.exe`, which matches nothing in that list, so it starts
//! and exits like any other program.
//!
//! # What it is for
//!
//! The one thing a caller like WinRAR's "scan with antivirus before opening"
//! needs: a path in, a verdict and an exit code out, with no service, no pipe and
//! no configuration to get wrong. Archives are opened rather than skipped, which
//! is the whole point of a caller that has just unpacked one.
//!
//! # Exit codes
//!
//! `0` clean, `1` malicious, `2` could not scan, `3` suspicious and
//! `--fail-on-suspicious` was given. The same table `wenle` uses, because a
//! caller that has one of them may be calling the other one day.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use av_core::{AvConfig, AvPaths, ScanOptions, Verdict};
use av_rules::database::RuleDatabase;
use av_scan::ScanEngine;

const CLEAN: u8 = 0;
const MALICIOUS: u8 = 1;
const FAILURE: u8 = 2;
const SUSPICIOUS: u8 = 3;

fn main() -> ExitCode {
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut fail_on_suspicious = false;
    let mut quiet = false;

    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--fail-on-suspicious" => fail_on_suspicious = true,
            "--quiet" | "-q" => quiet = true,
            "-h" | "--help" => {
                usage();
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("wenle-scan: unknown option {other}");
                usage();
                return ExitCode::from(FAILURE);
            }
            other => targets.push(PathBuf::from(other)),
        }
    }

    if targets.is_empty() {
        usage();
        return ExitCode::from(FAILURE);
    }

    match run(&targets, fail_on_suspicious, quiet) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("wenle-scan: {error}");
            ExitCode::from(FAILURE)
        }
    }
}

fn usage() {
    eprintln!(
        "wenle-scan {version}\n\
         \n\
         usage: wenle-scan [--quiet] [--fail-on-suspicious] <path>...\n\
         \n\
         Scans files and directory trees, and looks inside archives and other\n\
         containers. Exit codes: 0 clean, 1 malicious, 2 could not scan,\n\
         3 suspicious (only with --fail-on-suspicious).",
        version = env!("CARGO_PKG_VERSION")
    );
}

fn run(targets: &[PathBuf], fail_on_suspicious: bool, quiet: bool) -> Result<u8, String> {
    let paths = AvPaths::for_current_exe().map_err(|error| error.to_string())?;
    // Read, and do not fail: a configuration that cannot be parsed is the
    // product's problem and not the caller's, and a scanner that refuses to scan
    // because a file elsewhere is malformed is worse than one that uses the
    // defaults.
    let _config = AvConfig::load_or_default(&paths.config_file).unwrap_or_default();

    let database_path = paths.db_dir.join("rules.avdb");
    let database = RuleDatabase::load(&database_path)
        .map_err(|error| format!("reading {}: {error}", database_path.display()))?;
    let engine = ScanEngine::new(database);

    // Archives on, and deep enough for the nesting people actually produce. The
    // size cap keeps one enormous file from taking a caller's whole timeout.
    let mut options = ScanOptions::deep();
    options.archives = true;
    if options.archive_depth < 5 {
        options.archive_depth = 5;
    }
    options.max_file_size = Some(256 * 1024 * 1024);

    let mut examined = 0u64;
    let mut malicious = false;
    let mut unreadable = false;
    let mut suspicious = false;

    for target in targets {
        let mut files = Vec::new();
        collect(target, &mut files);
        if files.is_empty() {
            eprintln!("wenle-scan: nothing to scan at {}", target.display());
            unreadable = true;
            continue;
        }
        for file in files {
            let report = engine.scan_file(&file, &options);
            examined += 1;
            if let Some(error) = &report.error {
                // `ERROR_VIRUS_INFECTED` (225) is not a read failure: it is the
                // kernel refusing an open because this product has already
                // refused the file. Reporting it as "could not scan" would tell
                // a caller the opposite of what happened, and would give it exit
                // code 2 (try again later) for a file that is 1 (malicious).
                if error.contains("contains a virus") || error.contains("os error 225") {
                    malicious = true;
                    println!("{}: MALICIOUS (refused by the driver)", report.path.display());
                    continue;
                }
                println!("{}: could not scan: {error}", report.path.display());
                unreadable = true;
                continue;
            }
            match report.verdict() {
                Verdict::Malicious => {
                    malicious = true;
                    println!("{}: MALICIOUS", report.path.display());
                }
                Verdict::Suspicious => {
                    suspicious = true;
                    if !quiet {
                        println!("{}: suspicious", report.path.display());
                    }
                }
                _ => {
                    if !quiet {
                        println!("{}: clean", report.path.display());
                    }
                }
            }
        }
    }

    println!("{examined} file(s) examined");
    if malicious {
        return Ok(MALICIOUS);
    }
    if unreadable {
        return Ok(FAILURE);
    }
    if suspicious && fail_on_suspicious {
        return Ok(SUSPICIOUS);
    }
    Ok(CLEAN)
}

/// Every regular file at or under `path`.
///
/// A directory is walked recursively, files are the probe path unchanged, and
/// anything that is neither (a pipe, a device) is skipped rather than opened.
fn collect(path: &Path, out: &mut Vec<PathBuf>) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.is_file() {
        out.push(path.to_path_buf());
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect(&entry.path(), out);
    }
}
