//! In-memory session state for the daemon: the cached master key plus the
//! idle-timeout backstop.

use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::crypto::KEY_LEN;
use crate::error::{Result, VaultError};
use crate::keychain;

pub struct Session {
    key: Option<Zeroizing<[u8; KEY_LEN]>>,
    last_activity: Instant,
    idle_timeout: Duration,
}

impl Session {
    /// `idle_timeout` of zero disables the idle backstop.
    pub fn new(idle_timeout: Duration) -> Self {
        Session {
            key: None,
            last_activity: Instant::now(),
            idle_timeout,
        }
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// Trigger Touch ID, read the master key from the Keychain, and cache it.
    /// No-op (still bumps activity) if already unlocked.
    pub fn unlock(&mut self, reason: &str) -> Result<()> {
        if self.key.is_none() {
            let key = keychain::touch_id_unlock(reason)?;
            self.key = Some(Zeroizing::new(key));
        }
        self.touch();
        Ok(())
    }

    /// Cache an already-read key (used when the FFI read happened off-thread).
    pub fn set_key(&mut self, key: [u8; KEY_LEN]) {
        self.key = Some(Zeroizing::new(key));
        self.touch();
    }

    pub fn lock(&mut self) {
        // Zeroizing drops + wipes the key.
        self.key = None;
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Borrow the cached key, bumping activity. Errors if locked.
    pub fn key(&mut self) -> Result<&[u8; KEY_LEN]> {
        if self.key.is_none() {
            return Err(VaultError::Locked);
        }
        self.last_activity = Instant::now();
        Ok(self.key.as_ref().unwrap())
    }

    pub fn since_activity(&self) -> Duration {
        self.last_activity.elapsed()
    }

    pub fn idle_remaining(&self) -> Option<Duration> {
        if !self.is_unlocked() || self.idle_timeout.is_zero() {
            return None;
        }
        Some(self.idle_timeout.saturating_sub(self.since_activity()))
    }

    /// Relock if the idle timeout has elapsed. Returns true if it relocked.
    pub fn maybe_relock(&mut self) -> bool {
        if self.is_unlocked()
            && !self.idle_timeout.is_zero()
            && self.since_activity() >= self.idle_timeout
        {
            self.lock();
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_by_default() {
        let s = Session::new(Duration::from_secs(900));
        assert!(!s.is_unlocked());
        assert!(s.idle_remaining().is_none());
    }

    #[test]
    fn set_key_unlocks_and_lock_clears() {
        let mut s = Session::new(Duration::from_secs(900));
        s.set_key([7u8; KEY_LEN]);
        assert!(s.is_unlocked());
        assert_eq!(s.key().unwrap(), &[7u8; KEY_LEN]);
        s.lock();
        assert!(!s.is_unlocked());
        assert!(s.key().is_err());
    }

    #[test]
    fn idle_relock_fires() {
        let mut s = Session::new(Duration::from_millis(0)); // disabled
        s.set_key([1u8; KEY_LEN]);
        assert!(!s.maybe_relock()); // disabled never relocks

        let mut s = Session::new(Duration::from_nanos(1));
        s.set_key([1u8; KEY_LEN]);
        std::thread::sleep(Duration::from_millis(2));
        assert!(s.maybe_relock());
        assert!(!s.is_unlocked());
    }
}
