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
    unlocked_at: Instant,
    idle_timeout: Duration,
    max_session: Duration,
}

impl Session {
    /// `idle_timeout` and `max_session` of zero disable those backstops.
    pub fn new(idle_timeout: Duration, max_session: Duration) -> Self {
        let now = Instant::now();
        Session {
            key: None,
            last_activity: now,
            unlocked_at: now,
            idle_timeout,
            max_session,
        }
    }

    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    pub fn max_session(&self) -> Duration {
        self.max_session
    }

    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// Trigger Touch ID, read the master key from the Keychain, and cache it.
    /// No-op (still bumps activity) if already unlocked.
    pub fn unlock(&mut self, reason: &str) -> Result<()> {
        if self.key.is_none() {
            let key = keychain::touch_id_unlock(reason)?;
            self.set_key(key);
        } else {
            self.touch();
        }
        Ok(())
    }

    /// Cache an already-read key (used when the FFI read happened off-thread).
    pub fn set_key(&mut self, key: [u8; KEY_LEN]) {
        let was_locked = self.key.is_none();
        self.key = Some(Zeroizing::new(key));
        let now = Instant::now();
        self.last_activity = now;
        if was_locked {
            self.unlocked_at = now;
        }
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

    /// Time left before the absolute session cap relocks, if one is set.
    pub fn session_remaining(&self) -> Option<Duration> {
        if !self.is_unlocked() || self.max_session.is_zero() {
            return None;
        }
        Some(self.max_session.saturating_sub(self.unlocked_at.elapsed()))
    }

    /// Relock if the idle timeout OR the absolute session cap has elapsed.
    /// Returns the reason it relocked, if it did.
    pub fn maybe_relock(&mut self) -> Option<&'static str> {
        if !self.is_unlocked() {
            return None;
        }
        if !self.idle_timeout.is_zero() && self.since_activity() >= self.idle_timeout {
            self.lock();
            return Some("idle");
        }
        if !self.max_session.is_zero() && self.unlocked_at.elapsed() >= self.max_session {
            self.lock();
            return Some("max_session");
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_by_default() {
        let s = Session::new(Duration::from_secs(900), Duration::ZERO);
        assert!(!s.is_unlocked());
        assert!(s.idle_remaining().is_none());
        assert!(s.session_remaining().is_none());
    }

    #[test]
    fn set_key_unlocks_and_lock_clears() {
        let mut s = Session::new(Duration::from_secs(900), Duration::ZERO);
        s.set_key([7u8; KEY_LEN]);
        assert!(s.is_unlocked());
        assert_eq!(s.key().unwrap(), &[7u8; KEY_LEN]);
        s.lock();
        assert!(!s.is_unlocked());
        assert!(s.key().is_err());
    }

    #[test]
    fn external_lock_wipes_key_and_requires_reunlock() {
        // Mirrors the sleep / screen-lock observer firing on the shared session
        // (macOS run loop and Linux D-Bus both land here): the key is wiped and
        // any further access must re-authenticate. Same contract on both OSes.
        let mut s = Session::new(Duration::from_secs(900), Duration::ZERO);
        s.set_key([9u8; KEY_LEN]);
        assert!(s.is_unlocked());

        s.lock(); // what on_lock_event() invokes
        assert!(!s.is_unlocked());
        assert!(matches!(s.key(), Err(VaultError::Locked)));
        assert!(s.idle_remaining().is_none());
        assert!(s.session_remaining().is_none());
    }

    #[test]
    fn idle_relock_fires() {
        let mut s = Session::new(Duration::ZERO, Duration::ZERO); // both disabled
        s.set_key([1u8; KEY_LEN]);
        assert!(s.maybe_relock().is_none());

        let mut s = Session::new(Duration::from_nanos(1), Duration::ZERO);
        s.set_key([1u8; KEY_LEN]);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(s.maybe_relock(), Some("idle"));
        assert!(!s.is_unlocked());
    }

    #[test]
    fn max_session_relock_fires() {
        // idle disabled, tiny absolute cap -> relocks on cap.
        let mut s = Session::new(Duration::ZERO, Duration::from_nanos(1));
        s.set_key([1u8; KEY_LEN]);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(s.maybe_relock(), Some("max_session"));
        assert!(!s.is_unlocked());
    }
}
