//! Rate limiting and configuration for cloud lookups.
//!
//! abuse.ch gives its community API free of charge under fair use, and "fair
//! use" is measured in queries. A scanner that asks about every file it meets
//! would be a bad guest, so the client keeps a token bucket: a burst of a few
//! queries is fine, a sustained flood is not.

use std::time::{Duration, Instant};

/// What the settings file says about the cloud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudConfig {
    pub enabled: bool,
    pub provider: String,
    pub api_key: String,
    pub timeout_ms: u64,
    pub queries_per_minute: u32,
}

impl Default for CloudConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "malwarebazaar".to_string(),
            api_key: String::new(),
            timeout_ms: 3000,
            queries_per_minute: 60,
        }
    }
}

impl CloudConfig {
    /// Whether a lookup can be attempted at all.
    pub fn usable(&self) -> bool {
        self.enabled && !self.api_key.trim().is_empty()
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(500))
    }
}

/// A token bucket over one minute.
pub struct RateLimit {
    capacity: f64,
    tokens: f64,
    refilled: Instant,
}

impl RateLimit {
    pub fn per_minute(queries: u32) -> Self {
        let capacity = f64::from(queries.max(1));
        Self { capacity, tokens: capacity, refilled: Instant::now() }
    }

    /// Take one token, or say how long the caller should wait.
    pub fn take(&mut self, now: Instant) -> Result<(), Duration> {
        let elapsed = now.duration_since(self.refilled).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.capacity / 60.0).min(self.capacity);
        self.refilled = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            let missing = 1.0 - self.tokens;
            Err(Duration::from_secs_f64(missing * 60.0 / self.capacity))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_and_a_flood_is_not() {
        let mut limit = RateLimit::per_minute(3);
        let now = Instant::now();
        assert!(limit.take(now).is_ok());
        assert!(limit.take(now).is_ok());
        assert!(limit.take(now).is_ok());
        assert!(limit.take(now).is_err());
    }

    #[test]
    fn tokens_come_back_with_time() {
        let mut limit = RateLimit::per_minute(60);
        let start = Instant::now();
        assert!(limit.take(start).is_ok());
        assert!(limit.take(start).is_ok());
        let later = start + Duration::from_secs(2);
        assert!(limit.take(later).is_ok());
    }

    #[test]
    fn a_config_without_a_key_is_not_usable() {
        let mut config = CloudConfig::default();
        assert!(!config.usable());
        config.enabled = true;
        assert!(!config.usable());
        config.api_key = "key".to_string();
        assert!(config.usable());
    }
}
