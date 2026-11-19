//! Cloud reputation by hash.
//!
//! The contract this crate keeps is the one a user can read: a SHA-256 and
//! nothing else leaves the machine. Files are never uploaded, names are never
//! sent, and a lookup that fails or times out changes no local verdict -- the
//! local answer stands and the miss is logged.
//!
//! The first provider is MalwareBazaar by abuse.ch, which is free for open
//! source work and answers "is this hash a known sample" with the family name.
//! The interface is a trait so a second provider is a module, not a rewrite.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use av_core::Verdict;

pub mod config;
pub mod malwarebazaar;

/// What the cloud said about one hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudVerdict {
    /// A known sample, with whatever name the provider attached.
    Malicious { source: String, family: Option<String> },
    /// The provider answered and does not know this hash.
    Unknown,
    /// The question could not be asked: no key, no network, timeout.
    Unavailable { reason: String },
}

impl CloudVerdict {
    /// The verdict a scan result should carry, when the cloud knows better.
    pub fn raise(&self) -> Option<Verdict> {
        match self {
            CloudVerdict::Malicious { .. } => Some(Verdict::Malicious),
            _ => None,
        }
    }
}

/// One hash lookup service.
pub trait Provider: Send + Sync {
    fn name(&self) -> &str;

    /// Ask about a lowercase hexadecimal SHA-256.
    fn lookup(&self, sha256: &str) -> CloudVerdict;
}

/// A provider plus a cache, so a repeated hash costs nothing.
pub struct Cloud {
    provider: Box<dyn Provider>,
    cache: HashMap<String, (Instant, CloudVerdict)>,
    ttl: Duration,
}

impl Cloud {
    pub fn new(provider: Box<dyn Provider>) -> Self {
        Self { provider, cache: HashMap::new(), ttl: Duration::from_secs(24 * 60 * 60) }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Ask about a hash, caching the answer for a day.
    ///
    /// A malformed hash is answered as unavailable rather than sent: a provider
    /// that receives a path or a name is a provider that learns something the
    /// user did not agree to share.
    pub fn lookup(&mut self, sha256: &str) -> CloudVerdict {
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return CloudVerdict::Unavailable { reason: "not a SHA-256".to_string() };
        }
        let key = sha256.to_ascii_lowercase();
        if let Some((when, verdict)) = self.cache.get(&key) {
            if when.elapsed() < self.ttl {
                return verdict.clone();
            }
        }
        let verdict = self.provider.lookup(&key);
        if !matches!(verdict, CloudVerdict::Unavailable { .. }) {
            self.cache.insert(key, (Instant::now(), verdict.clone()));
        }
        verdict
    }
}

/// The cache never grows without bound: a scanning session can meet hundreds of
/// thousands of hashes, and a reputation cache is not an index of the disk.
pub fn prune(cache: &mut HashMap<String, (Instant, CloudVerdict)>, limit: usize) {
    if cache.len() <= limit {
        return;
    }
    let mut ages: Vec<(String, Instant)> =
        cache.iter().map(|(key, (when, _))| (key.clone(), *when)).collect();
    ages.sort_by_key(|(_, when)| *when);
    for (key, _) in ages.into_iter().take(cache.len() - limit) {
        cache.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counting {
        calls: AtomicUsize,
    }

    impl Provider for Counting {
        fn name(&self) -> &str {
            "counting"
        }

        fn lookup(&self, _sha256: &str) -> CloudVerdict {
            self.calls.fetch_add(1, Ordering::SeqCst);
            CloudVerdict::Malicious { source: "counting".to_string(), family: Some("Test".to_string()) }
        }
    }

    #[test]
    fn the_same_hash_is_asked_once() {
        let provider = Counting { calls: AtomicUsize::new(0) };
        let mut cloud = Cloud::new(Box::new(provider));
        let hash = "a".repeat(64);
        assert!(matches!(cloud.lookup(&hash), CloudVerdict::Malicious { .. }));
        assert!(matches!(cloud.lookup(&hash), CloudVerdict::Malicious { .. }));
        assert_eq!(cloud.cache.len(), 1);
    }

    #[test]
    fn a_path_is_not_a_hash_and_is_not_sent() {
        let provider = Counting { calls: AtomicUsize::new(0) };
        let mut cloud = Cloud::new(Box::new(provider));
        assert!(matches!(
            cloud.lookup("C:\\Windows\\notepad.exe"),
            CloudVerdict::Unavailable { .. }
        ));
        assert!(cloud.cache.is_empty());
    }

    #[test]
    fn an_unavailable_answer_is_not_cached() {
        struct Down;
        impl Provider for Down {
            fn name(&self) -> &str {
                "down"
            }
            fn lookup(&self, _sha256: &str) -> CloudVerdict {
                CloudVerdict::Unavailable { reason: "offline".to_string() }
            }
        }
        let mut cloud = Cloud::new(Box::new(Down));
        let hash = "b".repeat(64);
        assert!(matches!(cloud.lookup(&hash), CloudVerdict::Unavailable { .. }));
        assert!(cloud.cache.is_empty());
    }

    #[test]
    fn malicious_raises_a_clean_verdict() {
        let verdict = CloudVerdict::Malicious { source: "x".to_string(), family: None };
        assert_eq!(verdict.raise(), Some(Verdict::Malicious));
        assert_eq!(CloudVerdict::Unknown.raise(), None);
    }
}
