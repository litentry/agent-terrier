//! C ABI over the shared device crypto, for the ESP-IDF firmware (issue #367).
//!
//! Built only with `--features ffi` (+ `staticlib` crate-type) for the
//! `xtensa-esp32s3-none-elf` target; `cbindgen` generates `agentkeys_device.h`
//! from these signatures, so the firmware's C header cannot drift from the Rust
//! either. The firmware supplies entropy (`esp_fill_random`) and owns all
//! buffers; this module never allocates a key and never persists one — it only
//! runs the same curve math the broker verifies.
//!
//! Contract: every `out_*` pointer is a caller-owned buffer of at least the
//! documented capacity; string outputs are written NUL-terminated. Functions
//! return [`Ak::Ok`] on success or a negative code. Inputs are validated; a null
//! pointer or short buffer is an error, not a panic.
#![allow(unsafe_code)]

use core::ffi::{c_char, CStr};

use crate::{
    agent_pop_payload, delegation_payload, device_key_hash, eip191_sign, evm_address,
    signing_key_from_bytes,
};

/// Result codes returned across the C ABI.
#[repr(C)]
pub enum Ak {
    Ok = 0,
    NullPtr = -1,
    BadKey = -2,
    BufferTooSmall = -3,
    BadInput = -4,
    SignFailed = -5,
}

/// Write `s` (plus a NUL) into `out` if it fits in `cap`. Caller-owned buffer.
///
/// # Safety
/// `out` must point to at least `cap` writable bytes.
unsafe fn write_cstr(out: *mut c_char, cap: usize, s: &str) -> Ak {
    let bytes = s.as_bytes();
    if cap < bytes.len() + 1 {
        return Ak::BufferTooSmall;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
    *out.add(bytes.len()) = 0;
    Ak::Ok
}

/// Read a NUL-terminated UTF-8 C string, or `None` if null / not UTF-8.
///
/// # Safety
/// `p` must be null or point to a valid NUL-terminated C string.
unsafe fn read_cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// Generate a K10 from 32 caller-supplied entropy bytes.
///
/// `entropy`/`out_priv`: 32 bytes each (the validated scalar is copied to
/// `out_priv` — the firmware stores it in encrypted NVS). `out_addr`: >= 43 bytes
/// for the `0x`+40hex EVM address. Returns [`Ak::BadKey`] on the ~2^-128 chance
/// the entropy is not a valid scalar (re-sample).
///
/// # Safety
/// `entropy` and `out_priv` must point to 32 readable/writable bytes; `out_addr`
/// to `addr_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ak_device_keygen(
    entropy: *const u8,
    out_priv: *mut u8,
    out_addr: *mut c_char,
    addr_cap: usize,
) -> Ak {
    if entropy.is_null() || out_priv.is_null() || out_addr.is_null() {
        return Ak::NullPtr;
    }
    let entropy = core::slice::from_raw_parts(entropy, 32);
    let sk = match signing_key_from_bytes(entropy) {
        Ok(sk) => sk,
        Err(_) => return Ak::BadKey,
    };
    core::ptr::copy_nonoverlapping(entropy.as_ptr(), out_priv, 32);
    write_cstr(out_addr, addr_cap, &evm_address(sk.verifying_key()))
}

/// EVM address (`0x`+40hex) for the K10 already in `priv_` (32 bytes) — the load
/// path (NVS → address) complementing [`ak_device_keygen`]. `out` >= 43 bytes.
///
/// # Safety
/// `priv_` must point to 32 readable bytes; `out` to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ak_device_address(priv_: *const u8, out: *mut c_char, cap: usize) -> Ak {
    if priv_.is_null() || out.is_null() {
        return Ak::NullPtr;
    }
    let key_bytes = core::slice::from_raw_parts(priv_, 32);
    let sk = match signing_key_from_bytes(key_bytes) {
        Ok(sk) => sk,
        Err(_) => return Ak::BadKey,
    };
    write_cstr(out, cap, &evm_address(sk.verifying_key()))
}

/// `device_key_hash` (`0x`+64hex) for an EVM address string. `out` >= 67 bytes.
///
/// # Safety
/// `addr` must be a valid C string; `out` must point to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ak_device_key_hash(
    addr: *const c_char,
    out: *mut c_char,
    cap: usize,
) -> Ak {
    let addr = match read_cstr(addr) {
        Some(a) => a,
        None => return Ak::NullPtr,
    };
    match device_key_hash(addr) {
        Ok(h) => write_cstr(out, cap, &h),
        Err(_) => Ak::BadInput,
    }
}

/// EIP-191 agent proof-of-possession over the K10 in `priv_` (32 bytes):
/// `eip191_sign(agent_pop_payload(device_key_hash(address)))`. `out` >= 133 bytes
/// for the `0x`+130hex (`r||s||v`) signature the broker's §10.2 endpoints verify.
///
/// # Safety
/// `priv_` must point to 32 readable bytes; `out` to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ak_device_pop_sig(priv_: *const u8, out: *mut c_char, cap: usize) -> Ak {
    if priv_.is_null() || out.is_null() {
        return Ak::NullPtr;
    }
    let key_bytes = core::slice::from_raw_parts(priv_, 32);
    let sk = match signing_key_from_bytes(key_bytes) {
        Ok(sk) => sk,
        Err(_) => return Ak::BadKey,
    };
    let dkh = match device_key_hash(&evm_address(sk.verifying_key())) {
        Ok(h) => h,
        Err(_) => return Ak::BadInput,
    };
    match eip191_sign(&sk, &agent_pop_payload(&dkh)) {
        Ok(sig) => write_cstr(out, cap, &sig),
        Err(_) => Ak::SignFailed,
    }
}

/// EIP-191 device→sandbox delegation signature (issue #369) over the K10 in
/// `priv_` (32 bytes): `eip191_sign(delegation_payload(device_key_hash(addr),
/// sandbox_key, scope, expires_at))`. The device co-signs ONCE per sandbox spawn
/// to authorize `sandbox_key` to mint caps on its behalf, bounded by `scope` +
/// `expires_at`, WITHOUT ever exposing K10. `device_key_hash` is derived from
/// THIS key internally, so the firmware cannot delegate under another device's
/// hash. `out` >= 133 bytes for the `0x`+130hex (`r||s||v`) signature the worker
/// re-verifies (cf. [`ak_device_pop_sig`]).
///
/// # Safety
/// `priv_` must point to 32 readable bytes; `sandbox_key`/`scope` must be valid
/// C strings; `out` to `cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ak_device_delegation_sig(
    priv_: *const u8,
    sandbox_key: *const c_char,
    scope: *const c_char,
    expires_at: u64,
    out: *mut c_char,
    cap: usize,
) -> Ak {
    if priv_.is_null() || out.is_null() {
        return Ak::NullPtr;
    }
    let sandbox_key = match read_cstr(sandbox_key) {
        Some(s) => s,
        None => return Ak::NullPtr,
    };
    let scope = match read_cstr(scope) {
        Some(s) => s,
        None => return Ak::NullPtr,
    };
    let key_bytes = core::slice::from_raw_parts(priv_, 32);
    let sk = match signing_key_from_bytes(key_bytes) {
        Ok(sk) => sk,
        Err(_) => return Ak::BadKey,
    };
    let dkh = match device_key_hash(&evm_address(sk.verifying_key())) {
        Ok(h) => h,
        Err(_) => return Ak::BadInput,
    };
    let payload = delegation_payload(&dkh, sandbox_key, scope, expires_at);
    match eip191_sign(&sk, &payload) {
        Ok(sig) => write_cstr(out, cap, &sig),
        Err(_) => Ak::SignFailed,
    }
}
