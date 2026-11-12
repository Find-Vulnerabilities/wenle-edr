//! Verdicts by file content, not by file metadata.
//!
//! # Why the key is a digest
//!
//! A cache keyed by path, size and last-write time was added on 2026-11-08 and
//! removed the same day: every one of those fields is set by the owner of the
//! file, so the owner of a file that was refused could rewrite it and restore
//! the timestamp, and the gate would answer "clean" without looking. The audit
//! called that high severity and it was right.
//!
//! The key here is the SHA-256 of the file's bytes, computed by reading them.
//! A different file cannot have the same digest, so the hole above closes: to
//! hit the cache an attacker would have to produce a second preimage. Hashing is
//! the cheap part of the work by two orders of magnitude -- 22 MB reads in about
//! twenty milliseconds, where the rule engine needs six seconds for the same
//! file -- so a hit costs a read and saves the scan.
//!
//! # What is remembered, and what is not
//!
//! **Only a clean verdict, on a file that was read to the end.** A scan that
//! stopped at the size cap proves nothing about the bytes past the cap, and a
//! scan that ended in an error proves nothing at all; neither is remembered.
//! A conviction is not cached either: it is re-earned on the next question, so a
//! file that was fixed stops being refused.
//!
//! # Bounded
//!
//! [`DEFAULT_CAPACITY`] digests, least recently used first out. At sixty-five
//! bytes each that is under two megabytes, which is why this is affordable where
//! the old cache's bookkeeping was not the point.

use std::collections::{HashMap, VecDeque};
use std::path::Path;

/// How many digests are remembered.
pub const DEFAULT_CAPACITY: usize = 16_384;

/// The SHA-256 of `path`, or `None` when it cannot be read.
///
/// The file is read in chunks rather than whole: a gate decision about a 200 MB
/// image must not allocate 200 MB to decide it was seen before.
#[must_use]
pub fn digest_of(path: &Path) -> Option<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = av_core::hash::HashKind::Sha256.hasher();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => hasher.update(&buffer[..read]),
            // A file that cannot be read to the end has no digest this cache
            // may act on.
            Err(_) => return None,
        }
    }
    Some(hasher.finish())
}

/// Digests of files this service has read and found clean.
#[derive(Debug)]
pub struct VerdictCache {
    entries: HashMap<String, ()>,
    /// Least recently used first. A digest is moved to the back on every hit.
    order: VecDeque<String>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

impl VerdictCache {
    #[must_use]
    pub fn new(capacity: usize) -> VerdictCache {
        VerdictCache {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
            hits: 0,
            misses: 0,
        }
    }

    /// Whether this content was read and found clean before.
    pub fn is_known_clean(&mut self, digest: &str) -> bool {
        if !self.entries.contains_key(digest) {
            self.misses += 1;
            return false;
        }
        if let Some(index) = self.order.iter().position(|entry| entry == digest) {
            self.order.remove(index);
        }
        self.order.push_back(digest.to_string());
        self.hits += 1;
        true
    }

    /// Remember that this content was read to the end and found clean.
    pub fn remember_clean(&mut self, digest: &str) {
        if self.entries.contains_key(digest) {
            if let Some(index) = self.order.iter().position(|entry| entry == digest) {
                self.order.remove(index);
            }
        } else {
            while self.entries.len() >= self.capacity {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(digest.to_string(), ());
        self.order.push_back(digest.to_string());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Hits and misses since the service started, for the status report.
    #[must_use]
    pub fn counters(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("wenle-vc-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        dir.join("file.bin")
    }

    #[test]
    fn the_same_bytes_have_the_same_digest() {
        let path = temp("same");
        std::fs::write(&path, b"hello, this is a file").expect("write");
        let first = digest_of(&path).expect("digest");
        let second = digest_of(&path).expect("digest");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn changing_one_byte_changes_the_digest() {
        let path = temp("changed");
        std::fs::write(&path, b"one").expect("write");
        let before = digest_of(&path).expect("digest");
        std::fs::write(&path, b"two").expect("write");
        let after = digest_of(&path).expect("digest");
        assert_ne!(before, after, "a changed file must not hit the cache");
        let _ = std::fs::remove_dir_all(path.parent().expect("dir"));
    }

    #[test]
    fn a_remembered_digest_is_a_hit() {
        let mut cache = VerdictCache::new(4);
        assert!(!cache.is_known_clean("abc"));
        cache.remember_clean("abc");
        assert!(cache.is_known_clean("abc"));
        let (hits, misses) = cache.counters();
        assert_eq!(hits, 1);
        assert_eq!(misses, 1);
    }

    #[test]
    fn the_oldest_digest_is_evicted_first() {
        let mut cache = VerdictCache::new(2);
        cache.remember_clean("a");
        cache.remember_clean("b");
        assert!(cache.is_known_clean("a"));
        cache.remember_clean("c");
        assert_eq!(cache.len(), 2);
        assert!(!cache.is_known_clean("b"), "the least recently used survived");
        assert!(cache.is_known_clean("a"));
        assert!(cache.is_known_clean("c"));
    }
}
