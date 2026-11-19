//! `wenle cloud`: asking a reputation provider about one file, by hash.
//!
//! # What leaves the machine
//!
//! A SHA-256 and nothing else. No file contents, no file name, no path. The
//! hash is computed here, printed so the user can see exactly what would be
//! sent, and only then handed to the provider.
//!
//! # What the answer means
//!
//! A known hash is a fact the provider is asserting: it has this sample and has
//! labelled it. An unknown hash is *not* a clean file -- it means the provider
//! has never seen it, which is exactly the case the local engine and the model
//! exist for. The output says so, because "unknown to the cloud" read as
//! "clean" is the mistake this command is most likely to cause.
//!
//! # Why an API key is required
//!
//! abuse.ch requires an Auth-Key for its community API. The key is read from
//! `--api-key` or `WENLE_CLOUD_KEY`, never stored by this command, and never
//! written to a log.

use std::fs::File;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context as _, Result};
use av_cloud::malwarebazaar::MalwareBazaar;
use av_cloud::{Cloud, CloudVerdict};
use sha2::{Digest, Sha256};

use crate::cli::{CloudArgs, Globals};
use crate::commands::Context;
use crate::exit::Exit;

/// The hash of a file, read in chunks so that a large file is not resident.
fn hash_of(path: &std::path::Path) -> Result<String> {
    let mut file = File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

pub fn run(args: &CloudArgs, _globals: &Globals, _context: &Context) -> Result<Exit> {
    let digest = hash_of(&args.path)?;
    println!("file      {}", args.path.display());
    println!("sha256    {digest}");

    let key = args
        .api_key
        .clone()
        .or_else(|| std::env::var("WENLE_CLOUD_KEY").ok())
        .unwrap_or_default();
    if key.trim().is_empty() {
        println!("cloud     not asked: no API key");
        println!("          pass --api-key or set WENLE_CLOUD_KEY");
        println!("          abuse.ch gives a free key at https://auth.abuse.ch/");
        return Ok(Exit::Failure);
    }

    let provider = MalwareBazaar::new(key).with_timeout(Duration::from_millis(args.timeout_ms));
    let mut cloud = Cloud::new(Box::new(provider));
    match cloud.lookup(&digest) {
        CloudVerdict::Malicious { source, family } => {
            match family {
                Some(family) => println!("cloud     known malware: {family} (by {source})"),
                None => println!("cloud     known malware (by {source})"),
            }
            Ok(Exit::Malicious)
        }
        CloudVerdict::Unknown => {
            println!("cloud     unknown to the provider");
            println!("          unknown is not clean: the provider has never seen this hash");
            Ok(Exit::Clean)
        }
        CloudVerdict::Unavailable { reason } => {
            println!("cloud     could not ask: {reason}");
            Ok(Exit::Failure)
        }
    }
}
