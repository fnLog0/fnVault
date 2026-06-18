//! Linux backend: secret storage via the Secret Service (`keyring` crate, talks
//! to gnome-keyring / KWallet over D-Bus) and an unlock gate backed by a vault
//! passphrase (Argon2-verified).
//!
//! Rationale: a vault passphrase is the universally-available gate (set on first
//! unlock, verified thereafter — "unlock once per session", same as Touch ID on
//! macOS). When fprintd is present with an enrolled finger, a fingerprint scan
//! is tried *first* and the passphrase is the fallback — mirroring Touch ID's
//! "biometric, then passcode" flow. Sleep / screen-lock auto-lock is wired up
//! via D-Bus (see [`run_lock_observer`]). Set `FNVAULT_NO_FPRINT` to skip the
//! fingerprint attempt and always prompt for the passphrase.

use keyring::{Entry, Error as KrError};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::crypto::KEY_LEN;
use crate::error::{Result, VaultError};

const MASTER_SERVICE: &str = "fnvault.masterkey";
const MASTER_ACCOUNT: &str = "master";
const DATA_SERVICE: &str = "fnvault.data";
const AUTH_SERVICE: &str = "fnvault.auth";
const AUTH_ACCOUNT: &str = "verifier";
const SALT_LEN: usize = 16;

fn entry(service: &str, account: &str) -> Result<Entry> {
    Entry::new(service, account).map_err(|e| VaultError::Keychain(format!("keyring: {e}")))
}

fn read(service: &str, account: &str) -> Result<Option<Vec<u8>>> {
    match entry(service, account)?.get_secret() {
        Ok(v) => Ok(Some(v)),
        Err(KrError::NoEntry) => Ok(None),
        Err(e) => Err(VaultError::Keychain(format!("keyring read: {e}"))),
    }
}

fn write(service: &str, account: &str, data: &[u8]) -> Result<()> {
    entry(service, account)?
        .set_secret(data)
        .map_err(|e| VaultError::Keychain(format!("keyring write: {e}")))
}

fn remove(service: &str, account: &str) -> Result<()> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(KrError::NoEntry) => Ok(()),
        Err(e) => Err(VaultError::Keychain(format!("keyring delete: {e}"))),
    }
}

// ---- storage ------------------------------------------------------------

pub fn master_key_exists() -> bool {
    matches!(read(MASTER_SERVICE, MASTER_ACCOUNT), Ok(Some(_)))
}

pub fn store_master_key(key: &[u8; KEY_LEN]) -> Result<()> {
    write(MASTER_SERVICE, MASTER_ACCOUNT, key)
}

pub fn read_master_key() -> Result<[u8; KEY_LEN]> {
    let v = read(MASTER_SERVICE, MASTER_ACCOUNT)?.ok_or(VaultError::NotInitialized)?;
    if v.len() != KEY_LEN {
        return Err(VaultError::Keychain("master key has wrong length".into()));
    }
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&v);
    Ok(k)
}

pub fn delete_master_key() -> Result<()> {
    remove(MASTER_SERVICE, MASTER_ACCOUNT)
}

pub fn set_item(account: &str, data: &[u8]) -> Result<()> {
    write(DATA_SERVICE, account, data)
}

pub fn get_item(account: &str) -> Result<Option<Vec<u8>>> {
    read(DATA_SERVICE, account)
}

pub fn delete_item(account: &str) -> Result<()> {
    remove(DATA_SERVICE, account)
}

// ---- passphrase auth ----------------------------------------------------

/// Prompt for a passphrase from the (headless) daemon via systemd-ask-password.
fn ask(prompt: &str) -> Result<String> {
    let out = std::process::Command::new("systemd-ask-password")
        .arg(prompt)
        .output()
        .map_err(|_| {
            VaultError::Keychain(
                "no passphrase prompt available (need systemd-ask-password)".into(),
            )
        })?;
    if !out.status.success() {
        return Err(VaultError::AuthFailed);
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .to_string())
}

fn derive(pass: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let mut h = [0u8; KEY_LEN];
    argon2::Argon2::default()
        .hash_password_into(pass.as_bytes(), salt, &mut h)
        .map_err(|_| VaultError::Crypto)?;
    Ok(h)
}

/// Gate the session. On first unlock, set the vault passphrase (always the
/// recovery path). Thereafter, accept a matching fingerprint (fprintd) or, if
/// that's unavailable / doesn't match, the passphrase — Argon2 over the stored
/// salt. The same gate backs both the initial unlock and the per-read
/// re-authentication for sensitive (tiered) secrets.
pub fn touchid_authenticate(reason: &str) -> Result<()> {
    match read(AUTH_SERVICE, AUTH_ACCOUNT)? {
        None => {
            let p1 = ask("Set a passphrase for fnVault")?;
            if p1.is_empty() {
                return Err(VaultError::Keychain("passphrase must not be empty".into()));
            }
            let p2 = ask("Confirm fnVault passphrase")?;
            if p1 != p2 {
                return Err(VaultError::Keychain("passphrases do not match".into()));
            }
            let mut salt = [0u8; SALT_LEN];
            OsRng.fill_bytes(&mut salt);
            let h = derive(&p1, &salt)?;
            let mut blob = Vec::with_capacity(SALT_LEN + KEY_LEN);
            blob.extend_from_slice(&salt);
            blob.extend_from_slice(&h);
            write(AUTH_SERVICE, AUTH_ACCOUNT, &blob)
        }
        Some(blob) => {
            if blob.len() != SALT_LEN + KEY_LEN {
                return Err(VaultError::Keychain("corrupt auth verifier".into()));
            }
            // Biometric first (the Touch ID analog); passphrase is the fallback
            // when fprintd is absent, has no enrolled finger, or doesn't match.
            if fprintd_verify() {
                return Ok(());
            }
            let (salt, stored) = blob.split_at(SALT_LEN);
            let h = derive(&ask(reason)?, salt)?;
            if h.as_slice() == stored {
                Ok(())
            } else {
                Err(VaultError::AuthFailed)
            }
        }
    }
}

// ---- fprintd biometric gate ---------------------------------------------

/// Try to verify a fingerprint via fprintd. Returns `true` only on a match;
/// any other outcome (service missing, no enrolled finger, no match, scan
/// error, or disabled via `FNVAULT_NO_FPRINT`) returns `false` so the caller
/// falls back to the passphrase. Never blocks longer than fprintd's own verify
/// timeout.
fn fprintd_verify() -> bool {
    if std::env::var_os("FNVAULT_NO_FPRINT").is_some() {
        return false;
    }
    match fprintd_attempt() {
        Ok(matched) => matched,
        Err(e) => {
            // Non-fatal: no usable fingerprint reader -> passphrase fallback.
            eprintln!("fnvault: fingerprint unavailable ({e}); using passphrase");
            false
        }
    }
}

fn fprintd_attempt() -> zbus::Result<bool> {
    const SERVICE: &str = "net.reactivated.Fprint";
    let conn = zbus::blocking::Connection::system()?;

    // Resolve the default reader.
    let mgr = zbus::blocking::Proxy::new(
        &conn,
        SERVICE,
        "/net/reactivated/Fprint/Manager",
        "net.reactivated.Fprint.Manager",
    )?;
    let device: zbus::zvariant::OwnedObjectPath = mgr.call("GetDefaultDevice", &())?;

    let dev = zbus::blocking::Proxy::new(
        &conn,
        SERVICE,
        device.as_str().to_string(),
        "net.reactivated.Fprint.Device",
    )?;

    // "" = the calling user. No enrolled finger -> nothing to verify against.
    let enrolled: Vec<String> = dev.call("ListEnrolledFingers", &"")?;
    if enrolled.is_empty() {
        return Ok(false);
    }

    let _: () = dev.call("Claim", &"")?;
    // Subscribe before VerifyStart so no status signal is missed.
    let outcome = (|| -> zbus::Result<bool> {
        let signals = dev.receive_signal("VerifyStatus")?;
        let _: () = dev.call("VerifyStart", &"any")?;
        for msg in signals {
            let body = msg.body();
            let (result, done): (String, bool) = body.deserialize()?;
            if result == "verify-match" {
                return Ok(true);
            }
            if result == "verify-no-match" || done {
                return Ok(false);
            }
            // Transient (verify-retry-scan, verify-swipe-too-short, …): wait.
        }
        Ok(false)
    })();
    // Best-effort teardown regardless of the verify result.
    let _: zbus::Result<()> = dev.call("VerifyStop", &());
    let _: zbus::Result<()> = dev.call("Release", &());
    outcome
}

pub fn touch_id_unlock(reason: &str) -> Result<[u8; KEY_LEN]> {
    touchid_authenticate(reason)?;
    read_master_key()
}

// ---- lock-event observer ------------------------------------------------

/// When to fire the relock callback for a given signal.
enum RelockOn {
    /// Fire on every emission (signal carries no useful argument).
    Always,
    /// Fire only when the first boolean argument is `true` (e.g. "going to
    /// sleep" / "screensaver became active").
    BoolArgTrue,
}

/// Subscribe to one D-Bus signal and, on a dedicated thread, relock via `cb`
/// whenever it fires per `mode`. Returns the join handle, or `None` if the
/// match rule / subscription could not be set up (the caller carries on with
/// whatever other sources succeeded).
fn watch(
    conn: &zbus::blocking::Connection,
    interface: &str,
    member: &str,
    cb: extern "C" fn(),
    mode: RelockOn,
) -> Option<std::thread::JoinHandle<()>> {
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(interface.to_string())
        .ok()?
        .member(member.to_string())
        .ok()?
        .build();
    let iter = zbus::blocking::MessageIterator::for_match_rule(rule, conn, None).ok()?;
    Some(std::thread::spawn(move || {
        for msg in iter {
            let Ok(msg) = msg else { continue };
            let fire = match mode {
                RelockOn::Always => true,
                RelockOn::BoolArgTrue => msg.body().deserialize::<bool>().unwrap_or(false),
            };
            if fire {
                cb();
            }
        }
    }))
}

/// Relock on system sleep and screen lock by listening for D-Bus signals:
///
/// - **system bus** — logind `PrepareForSleep(true)` (suspend/hibernate) and
///   `Session.Lock` (`loginctl lock-session`, emitted by most desktops on lock);
/// - **session bus** — freedesktop `ScreenSaver.ActiveChanged(true)`.
///
/// Each source runs on its own thread; this call blocks until they all end
/// (which is effectively never). If no bus / signal is reachable (headless box,
/// no session bus), it parks instead — the daemon's idle-timeout backstop still
/// relocks. Mirrors the macOS observer's run-loop contract: call from a
/// dedicated thread.
pub fn run_lock_observer(cb: extern "C" fn()) {
    let mut handles = Vec::new();

    match zbus::blocking::Connection::system() {
        Ok(conn) => {
            handles.extend(watch(
                &conn,
                "org.freedesktop.login1.Manager",
                "PrepareForSleep",
                cb,
                RelockOn::BoolArgTrue,
            ));
            handles.extend(watch(
                &conn,
                "org.freedesktop.login1.Session",
                "Lock",
                cb,
                RelockOn::Always,
            ));
        }
        Err(e) => eprintln!("fnvault: no system bus for lock observer ({e}); idle timeout still active"),
    }

    if let Ok(conn) = zbus::blocking::Connection::session() {
        handles.extend(watch(
            &conn,
            "org.freedesktop.ScreenSaver",
            "ActiveChanged",
            cb,
            RelockOn::BoolArgTrue,
        ));
    }

    if handles.is_empty() {
        // Nothing to observe; keep the thread alive so the daemon's contract
        // (an observer thread that never returns) still holds.
        loop {
            std::thread::park();
        }
    }

    for h in handles {
        let _ = h.join();
    }
}
