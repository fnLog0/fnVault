//! Safe Rust wrappers over the Objective-C Keychain/Touch ID shim
//! (`keychain_shim.m`).

use std::ffi::CString;

use crate::crypto::KEY_LEN;
use crate::error::{Result, VaultError};

mod ffi {
    use std::os::raw::c_char;
    extern "C" {
        pub fn fnvault_touchid_authenticate(reason: *const c_char) -> i32;
        pub fn fnvault_master_key_exists() -> i32;
        pub fn fnvault_store_master_key(data: *const u8, len: usize) -> i32;
        pub fn fnvault_read_master_key(out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32;
        pub fn fnvault_delete_master_key() -> i32;
        pub fn fnvault_set_item(account: *const c_char, data: *const u8, len: usize) -> i32;
        pub fn fnvault_get_item(
            account: *const c_char,
            out: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32;
        pub fn fnvault_delete_item(account: *const c_char) -> i32;
        pub fn fnvault_free(p: *mut u8);
        pub fn fnvault_run_lock_observer(cb: extern "C" fn());
    }
}

/// Register for system sleep / screen-lock and run this thread's run loop,
/// invoking `cb` on either event. Blocks forever — call from a dedicated thread.
pub fn run_lock_observer(cb: extern "C" fn()) {
    unsafe { ffi::fnvault_run_lock_observer(cb) }
}

fn cstr(s: &str) -> Result<CString> {
    CString::new(s).map_err(|_| VaultError::Keychain("invalid account string".into()))
}

pub fn master_key_exists() -> bool {
    unsafe { ffi::fnvault_master_key_exists() == 1 }
}

pub fn store_master_key(key: &[u8; KEY_LEN]) -> Result<()> {
    let r = unsafe { ffi::fnvault_store_master_key(key.as_ptr(), key.len()) };
    if r == 0 {
        Ok(())
    } else {
        Err(VaultError::Keychain(format!(
            "failed to store master key (code {r}); is a device passcode set?"
        )))
    }
}

/// Prompt Touch ID (with passcode fallback) and block until the user responds.
pub fn touchid_authenticate(reason: &str) -> Result<()> {
    let reason_c = cstr(reason)?;
    let r = unsafe { ffi::fnvault_touchid_authenticate(reason_c.as_ptr()) };
    match r {
        0 => Ok(()),
        2 => Err(VaultError::Keychain(
            "no authentication method available (set a device passcode)".into(),
        )),
        _ => Err(VaultError::AuthFailed),
    }
}

/// Read the raw master key bytes. Does not prompt — gate with
/// [`touchid_authenticate`] first.
pub fn read_master_key() -> Result<[u8; KEY_LEN]> {
    let mut out = [0u8; KEY_LEN];
    let mut len: usize = 0;
    let r = unsafe { ffi::fnvault_read_master_key(out.as_mut_ptr(), KEY_LEN, &mut len) };
    match r {
        0 if len == KEY_LEN => Ok(out),
        _ => Err(VaultError::Keychain(format!(
            "read master key failed (code {r})"
        ))),
    }
}

/// Touch ID gate followed by a master-key read — the full unlock step.
pub fn touch_id_unlock(reason: &str) -> Result<[u8; KEY_LEN]> {
    touchid_authenticate(reason)?;
    read_master_key()
}

pub fn delete_master_key() -> Result<()> {
    let r = unsafe { ffi::fnvault_delete_master_key() };
    if r == 0 {
        Ok(())
    } else {
        Err(VaultError::Keychain("failed to delete master key".into()))
    }
}

pub fn set_item(account: &str, data: &[u8]) -> Result<()> {
    let acct = cstr(account)?;
    let r = unsafe { ffi::fnvault_set_item(acct.as_ptr(), data.as_ptr(), data.len()) };
    if r == 0 {
        Ok(())
    } else {
        Err(VaultError::Keychain(format!(
            "failed to store item `{account}`"
        )))
    }
}

pub fn get_item(account: &str) -> Result<Option<Vec<u8>>> {
    let acct = cstr(account)?;
    let mut ptr: *mut u8 = std::ptr::null_mut();
    let mut len: usize = 0;
    let r = unsafe { ffi::fnvault_get_item(acct.as_ptr(), &mut ptr, &mut len) };
    match r {
        0 => {
            let v = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
            unsafe { ffi::fnvault_free(ptr) };
            Ok(Some(v))
        }
        1 => Ok(None),
        _ => Err(VaultError::Keychain(format!(
            "failed to read item `{account}`"
        ))),
    }
}

pub fn delete_item(account: &str) -> Result<()> {
    let acct = cstr(account)?;
    let r = unsafe { ffi::fnvault_delete_item(acct.as_ptr()) };
    if r == 0 {
        Ok(())
    } else {
        Err(VaultError::Keychain(format!(
            "failed to delete item `{account}`"
        )))
    }
}
