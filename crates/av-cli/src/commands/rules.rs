//! `wenle rules` — the rule database, and where it comes from.
//!
//! # No rules are shipped
//!
//! The database is other people's work under other people's licences, so the
//! release carries none; this command is how a machine gets some. It downloads
//! the YARA-Forge extended package, compiles it with the same compiler
//! `wenle build` uses, and installs the result where the service reads it.
//!
//! # The digest is checked against the release, not computed from the download
//!
//! A hash this program computes from a file it has just downloaded proves only
//! that the bytes it hashed are the bytes it has. An attacker who can replace
//! the download can replace what it hashes. What makes the check mean something
//! is a reference the attacker cannot change: GitHub computes a SHA-256 for
//! every release asset and returns it in the release metadata. The package is
//! therefore resolved through the API, its digest remembered, and the download
//! refused unless the bytes hash to exactly that. An attacker who can also
//! change the metadata has compromised GitHub's TLS, which is outside what this
//! program can defend.
//!
//! After installation a small `rules.lock` records the digest of the compiled
//! database and the release it came from. `status` recomputes it, so a database
//! replaced by something else on the machine is visible rather than assumed.
//!
//! # The three verbs
//!
//! * `status` says what is installed and what is published, and changes
//!   nothing.
//! * `update` downloads, verifies, compiles and installs, keeping the previous
//!   database as `rules.avdb.before-feed`. It stops the service while the file
//!   it has open is replaced, and starts it again afterwards.
//! * `auto on|off` writes `[rules] auto_update` in `config.toml`, which the
//!   service reads to decide whether it updates the database itself.

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use av_archive::budget::ExpansionBudget;
use av_archive::zip::ZipArchive;
use av_rules::database::RuleDatabase;
use sha2::{Digest, Sha256};

use crate::cli::{Globals, RulesArgs, RulesCommand};
use crate::commands::{Context, DATABASE_FILE};
use crate::exit::Exit;

/// Where the extended package is published.
///
/// The API is used to resolve it so that the release's own digest comes with
/// it; this constant is the fallback a person is told about when the API cannot
/// be reached.
pub const FEED_URL: &str =
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip";

/// The release metadata that carries the digest.
const RELEASE_API: &str = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest";

/// The asset inside that release.
const ASSET_NAME: &str = "yara-forge-rules-extended.zip";

/// How large a package this will accept, before and after decompression.
///
/// The extended package is about forty megabytes; a ceiling four times that
/// leaves room for it to grow and still refuses an archive that would expand
/// into something the machine cannot hold.
const PACKAGE_LIMIT: u64 = 512 * 1024 * 1024;

/// The file that records what was installed.
const LOCK_FILE: &str = "rules.lock";

pub fn run(args: &RulesArgs, globals: &Globals, context: &Context) -> Result<Exit> {
    match &args.command {
        RulesCommand::Status => status(globals, context),
        RulesCommand::Update {
            url,
            from,
            digest,
            allow_unverified,
            no_restart,
            dry_run,
        } => update(
            url.as_deref(),
            from.as_deref(),
            digest.as_deref(),
            *allow_unverified,
            *no_restart,
            *dry_run,
            context,
        ),
        RulesCommand::Auto { state } => auto(state, context),
    }
}

/// What is installed, and what is published.
fn status(_globals: &Globals, context: &Context) -> Result<Exit> {
    let database = context.paths.db_dir.join(DATABASE_FILE);
    println!("Installed");
    if database.is_file() {
        let metadata = std::fs::metadata(&database)?;
        println!(
            "  {}  {:.1} MB  {}",
            database.display(),
            metadata.len() as f64 / (1024.0 * 1024.0),
            modified(&metadata)
        );
        match RuleDatabase::load(&database) {
            Ok(loaded) => println!("  {} rules", loaded.len()),
            Err(error) => println!("  could not be read: {error}"),
        }
        match read_lock(&context.paths.db_dir) {
            Some(lock) => {
                let installed = std::fs::read(&database).ok().map(|bytes| sha256_hex(&bytes));
                println!("  release {}", lock.release);
                match installed {
                    Some(digest) if digest.eq_ignore_ascii_case(&lock.database) => {
                        println!("  digest {} (matches rules.lock)", short(&lock.database));
                    }
                    Some(digest) => {
                        println!(
                            "  digest {} (rules.lock says {}): the database on disk is not the \
                             one that was installed",
                            short(&digest),
                            short(&lock.database)
                        );
                    }
                    None => println!("  the database could not be read to check it"),
                }
            }
            None => println!("  no rules.lock; this database was not installed by `wenle rules`"),
        }
    } else {
        println!("  no rule database; run `wenle rules update`");
    }

    println!();
    println!("Published");
    match latest_asset() {
        Ok(asset) => {
            println!("  release {} ({})", asset.release, asset.url);
            match &asset.digest {
                Some(digest) => println!("  digest  {digest}"),
                None => println!("  the release publishes no digest for this asset"),
            }
        }
        Err(error) => {
            println!("  the release metadata could not be read: {error}");
            println!("  fallback: {FEED_URL}");
        }
    }

    println!();
    println!(
        "Automatic update: {}",
        if auto_update_is_on(&context.paths.config_file) {
            "on"
        } else {
            "off"
        }
    );
    Ok(Exit::Clean)
}

/// Download (or read from a file), verify, compile, and install.
fn update(
    url: Option<&str>,
    from: Option<&Path>,
    digest: Option<&str>,
    allow_unverified: bool,
    no_restart: bool,
    dry_run: bool,
    context: &Context,
) -> Result<Exit> {
    let (bytes, release) = match from {
        Some(path) => {
            println!("Reading {}", path.display());
            let bytes =
                std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            (bytes, format!("file:{}", path.display()))
        }
        None => {
            let asset = match url {
                Some(url) => Asset {
                    release: url.to_string(),
                    url: url.to_string(),
                    digest: digest.map(str::to_string),
                },
                None => latest_asset()?,
            };
            let expected = digest
                .map(str::to_string)
                .or_else(|| asset.digest.clone());
            println!("Downloading {}", asset.url);
            let bytes = download(&asset.url)?;
            match &expected {
                Some(expected) => verify(&bytes, expected)?,
                None if allow_unverified => {
                    println!("  no digest to check against; --allow-unverified says to continue");
                }
                None => bail!(
                    "the release publishes no digest for this package, so the download cannot be \
                     checked; pass --allow-unverified to accept it anyway"
                ),
            }
            (bytes, asset.release)
        }
    };
    if let (Some(expected), Some(_)) = (digest, from) {
        verify(&bytes, expected)?;
    }
    println!(
        "  {} bytes, sha256 {}",
        bytes.len(),
        short(&sha256_hex(&bytes))
    );

    install_package(&context.paths.db_dir, &bytes, &release, no_restart, dry_run)
}

/// Compile a verified package and put it where the service reads it.
///
/// Shared by the command line and by the update script's `update.rules()`
/// step, so a script and a command line cannot install different things.
pub(crate) fn install_package(
    db_dir: &Path,
    bytes: &[u8],
    release: &str,
    no_restart: bool,
    dry_run: bool,
) -> Result<Exit> {
    let rules = extract(bytes)?;
    println!("  {} bytes of rule sources", rules.len());

    println!("Compiling");
    let (compiled, report) = RuleDatabase::compile(&rules);
    println!("  {} rules, {} refused", compiled.len(), report.refused());
    if compiled.is_empty() {
        bail!("every rule was refused; nothing was written and nothing changed");
    }

    let database = db_dir.join(DATABASE_FILE);
    if dry_run {
        println!("Dry run: {} would be replaced", database.display());
        return Ok(Exit::Clean);
    }

    // Written beside the target and read back before it is installed: a
    // database that cannot be parsed is not one to put where the service reads
    // it, and finding that out now is cheaper than finding it out at start-up.
    let staged = database.with_extension("avdb.new");
    compiled
        .save(&staged)
        .with_context(|| format!("writing {}", staged.display()))?;
    RuleDatabase::load(&staged).context("the compiled database could not be read back")?;
    let digest_of_database = std::fs::read(&staged)
        .map(|bytes| sha256_hex(&bytes))
        .unwrap_or_default();

    if database.is_file() {
        let backup = database.with_extension("avdb.before-feed");
        std::fs::copy(&database, &backup)
            .with_context(|| format!("backing up to {}", backup.display()))?;
        println!("  previous database kept at {}", backup.display());
    }

    // The service holds the database open; replacing a file it has mapped is
    // the reason installs of this product needed a reboot in November 2026.
    let stopped = if no_restart { false } else { stop_service() };
    let installed = std::fs::rename(&staged, &database)
        .with_context(|| format!("installing {}", database.display()));
    if stopped {
        start_service();
    }
    installed?;

    write_lock(
        db_dir,
        &Lock {
            database: digest_of_database,
            release: release.to_string(),
            installed: now(),
        },
    )?;

    println!("Installed {}", database.display());
    Ok(Exit::Clean)
}

/// The whole feed update, for a caller that has only the data directory.
///
/// This is what the update script's `update.rules()` step runs. It refuses a
/// release that publishes no digest rather than trusting the download.
pub(crate) fn install_feed(db_dir: &Path) -> Result<()> {
    let asset = latest_asset()?;
    let bytes = download(&asset.url)?;
    match &asset.digest {
        Some(digest) => verify(&bytes, digest)?,
        None => bail!(
            "the release publishes no digest for this package; refusing to install what cannot \
             be checked"
        ),
    }
    install_package(db_dir, &bytes, &asset.release, false, false)?;
    Ok(())
}

/// Turn `[rules] auto_update` on or off in the configuration.
fn auto(state: &str, context: &Context) -> Result<Exit> {
    let on = match state {
        "on" | "true" | "yes" => true,
        "off" | "false" | "no" => false,
        other => bail!("expected on or off, not {other}"),
    };
    let path = context.paths.config_file.clone();
    let body = std::fs::read_to_string(&path).unwrap_or_default();
    let updated = set_auto_update(&body, on);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&path, updated).with_context(|| format!("writing {}", path.display()))?;
    println!(
        "Automatic rule updates: {} ({}).",
        if on { "on" } else { "off" },
        path.display()
    );
    println!("The service reads this at start-up; restart it for the change to take effect.");
    Ok(Exit::Clean)
}

/// A release asset and the digest the release publishes for it.
struct Asset {
    release: String,
    url: String,
    digest: Option<String>,
}

fn latest_asset() -> Result<Asset> {
    let response = ureq::get(RELEASE_API)
        .set("User-Agent", "wenle-edr")
        .timeout(Duration::from_secs(30))
        .call()
        .map_err(|error| anyhow!("{error}"))?;
    let text = response
        .into_string()
        .context("the release metadata could not be read")?;
    let body: serde_json::Value =
        serde_json::from_str(&text).context("the release metadata was not JSON")?;
    let release = body["tag_name"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let assets = body["assets"]
        .as_array()
        .ok_or_else(|| anyhow!("the release metadata lists no assets"))?;
    let asset = assets
        .iter()
        .find(|asset| asset["name"].as_str() == Some(ASSET_NAME))
        .ok_or_else(|| anyhow!("release {release} has no {ASSET_NAME}"))?;
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| anyhow!("the asset has no download URL"))?
        .to_string();
    let digest = asset["digest"].as_str().map(str::to_string);
    Ok(Asset {
        release,
        url,
        digest,
    })
}

fn download(url: &str) -> Result<Vec<u8>> {
    let response = ureq::get(url)
        .set("User-Agent", "wenle-edr")
        .timeout(Duration::from_secs(300))
        .call()
        .map_err(|error| anyhow!("the package could not be fetched: {error}"))?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(PACKAGE_LIMIT)
        .read_to_end(&mut bytes)
        .context("reading the package")?;
    if bytes.is_empty() {
        bail!("the package was empty");
    }
    Ok(bytes)
}

/// Refuse the bytes unless they hash to the expected digest.
///
/// The expected value is GitHub's `sha256:`-prefixed asset digest, but a bare
/// hex digest is accepted too, because a person pasting a value by hand will.
fn verify(bytes: &[u8], expected: &str) -> Result<()> {
    let expected = expected
        .strip_prefix("sha256:")
        .unwrap_or(expected)
        .trim()
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the expected digest is not a SHA-256 value: {expected}");
    }
    let actual = sha256_hex(bytes);
    if actual != expected {
        bail!(
            "the package does not match the digest the release publishes: expected {expected}, \
             the downloaded bytes hash to {actual}. Nothing was changed."
        );
    }
    println!("  the download matches the published digest");
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn short(digest: &str) -> &str {
    &digest[..digest.len().min(16)]
}

/// The largest `.yar` member of the package, as text.
fn extract(package: &[u8]) -> Result<String> {
    let archive =
        ZipArchive::parse(package).map_err(|error| anyhow!("the package is not a zip: {error}"))?;
    let (index, _) = archive
        .entries()
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            !entry.directory && entry.name.to_ascii_lowercase().ends_with(".yar")
        })
        .max_by_key(|(_, entry)| entry.uncompressed_size)
        .ok_or_else(|| anyhow!("the package holds no .yar file"))?;
    let mut budget = ExpansionBudget::new(PACKAGE_LIMIT, PACKAGE_LIMIT);
    let extracted = archive
        .read(index, &mut budget)
        .map_err(|error| anyhow!("reading the rules out of the package: {error}"))?;
    String::from_utf8(extracted.bytes)
        .map_err(|_| anyhow!("the rule file is not UTF-8, which this compiler cannot read"))
}

/// What `rules.lock` records.
struct Lock {
    database: String,
    release: String,
    installed: u64,
}

fn lock_path(db_dir: &Path) -> PathBuf {
    db_dir.join(LOCK_FILE)
}

fn read_lock(db_dir: &Path) -> Option<Lock> {
    let body = std::fs::read_to_string(lock_path(db_dir)).ok()?;
    let mut lock = Lock {
        database: String::new(),
        release: String::new(),
        installed: 0,
    };
    for line in body.lines() {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "database" => lock.database = value.to_string(),
            "release" => lock.release = value.to_string(),
            "installed" => lock.installed = value.parse().unwrap_or(0),
            _ => {}
        }
    }
    Some(lock)
}

fn write_lock(db_dir: &Path, lock: &Lock) -> Result<()> {
    let body = format!(
        "database {}\nrelease {}\ninstalled {}\n",
        lock.database, lock.release, lock.installed
    );
    std::fs::write(lock_path(db_dir), body).context("writing rules.lock")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The service's name.
///
/// Repeated here rather than imported: `av-service` is a dependency of this
/// crate for the protocol end, and its constant is not part of what that crate
/// exports for a caller. One string in two places is the cost of not widening
/// that surface.
const SERVICE_NAME: &str = "WenleAvService";

/// Whether `[rules] auto_update` is on in this configuration.
///
/// Read as text rather than parsed, because this command's subject is the file
/// and an unreadable file must answer "off" rather than "this command cannot
/// run". The service parses it properly when it starts.
fn auto_update_is_on(path: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(path) else {
        return false;
    };
    let mut in_rules = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_rules = trimmed == "[rules]";
            continue;
        }
        if in_rules && trimmed.starts_with("auto_update") {
            return trimmed
                .split('=')
                .nth(1)
                .map(|value| {
                    let value = value.trim().trim_matches('"');
                    value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("on")
                })
                .unwrap_or(false);
        }
    }
    false
}

fn stop_service() -> bool {
    println!("  stopping the service so the database is not in use");
    let stopped = std::process::Command::new("sc.exe")
        .args(["stop", SERVICE_NAME])
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    let mut waited = 0;
    while waited < 60 && process_is_running() {
        std::thread::sleep(Duration::from_secs(1));
        waited += 1;
    }
    stopped
}

fn start_service() {
    println!("  starting the service");
    let _ = std::process::Command::new("sc.exe")
        .args(["start", SERVICE_NAME])
        .status();
}

#[cfg(windows)]
fn process_is_running() -> bool {
    let output = std::process::Command::new("tasklist.exe")
        .args(["/FI", "IMAGENAME eq wenle-av-service.exe", "/NH"])
        .output();
    match output {
        Ok(output) => String::from_utf8_lossy(&output.stdout).contains("wenle-av-service"),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn process_is_running() -> bool {
    false
}

fn modified(metadata: &std::fs::Metadata) -> String {
    metadata
        .modified()
        .ok()
        .map(|time| {
            let seconds = time
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0);
            format!("mtime {seconds}")
        })
        .unwrap_or_else(|| "mtime unknown".to_string())
}

/// The configuration text with `[rules] auto_update` set to `on`.
///
/// Textual rather than a TOML round trip, because a round trip through a value
/// table would rewrite every comment in a file a person may have edited. The
/// table is appended when it is not there and the key is replaced in place when
/// it is; a `[rules]` table with other keys keeps them.
fn set_auto_update(body: &str, on: bool) -> String {
    let value = format!("auto_update = {}", on);
    let mut lines: Vec<String> = body.lines().map(str::to_string).collect();
    let mut in_rules = false;
    let mut seen_table = false;
    let mut seen_key = false;
    let mut table_end = None;
    for (index, line) in lines.iter_mut().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_rules && table_end.is_none() {
                table_end = Some(index);
            }
            in_rules = trimmed == "[rules]";
            if in_rules {
                seen_table = true;
                table_end = None;
            }
            continue;
        }
        if in_rules && trimmed.starts_with("auto_update") && trimmed.contains('=') {
            *line = value.clone();
            seen_key = true;
        }
    }
    if seen_table && !seen_key {
        let at = table_end.unwrap_or(lines.len());
        lines.insert(at, value);
    } else if !seen_table {
        if !lines.is_empty() && !lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.push(String::new());
        }
        lines.push("[rules]".to_string());
        lines.push(value);
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::{sha256_hex, set_auto_update, verify};

    #[test]
    fn a_configuration_without_a_rules_table_gets_one() {
        let body = "[general]\nstart_with_windows = true\n";
        let updated = set_auto_update(body, true);
        assert!(updated.contains("[rules]"));
        assert!(updated.contains("auto_update = true"));
        assert!(updated.contains("start_with_windows = true"));
    }

    #[test]
    fn an_existing_key_is_replaced_and_not_duplicated() {
        let body = "[rules]\nauto_update = false\ntier = \"extended\"\n";
        let updated = set_auto_update(body, true);
        assert_eq!(updated.matches("auto_update").count(), 1);
        assert!(updated.contains("auto_update = true"));
        assert!(updated.contains("tier = \"extended\""));
        assert!(!updated.contains("auto_update = false"));
    }

    #[test]
    fn a_matching_digest_is_accepted_and_a_different_one_is_refused() {
        let bytes = b"the package";
        let digest = sha256_hex(bytes);
        assert!(verify(bytes, &digest).is_ok());
        assert!(verify(bytes, &format!("sha256:{digest}")).is_ok());
        assert!(verify(bytes, &"0".repeat(64)).is_err());
        assert!(verify(bytes, "not-a-digest").is_err());
    }

    #[test]
    fn the_digest_of_the_empty_string_is_the_published_one() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
