use starknet_crypto::sign;
use starknet_crypto::verify;
use starknet_crypto::get_public_key;
use starknet_crypto::rfc6979_generate_k;
use starknet_crypto::Felt;
use starknet_crypto::SignError;

const FELT_LEN: usize = 32;

/// ECDSA sign: (private_key, message_hash, k) -> (r, s). All buffers 32 bytes LE.
/// Returns: 0 = success, 1 = InvalidMessageHash, 2 = InvalidK, -1 = null/invalid args.
#[no_mangle]
pub extern "C" fn starknet_crypto_sign(
    priv_key_ptr: *const u8,
    hash_ptr: *const u8,
    k_ptr: *const u8,
    r_out_ptr: *mut u8,
    s_out_ptr: *mut u8,
) -> i32 {
    if priv_key_ptr.is_null()
        || hash_ptr.is_null()
        || k_ptr.is_null()
        || r_out_ptr.is_null()
        || s_out_ptr.is_null()
    {
        return -1;
    }
    let priv_key = slice_to_felt(unsafe { std::slice::from_raw_parts(priv_key_ptr, FELT_LEN) });
    let hash = slice_to_felt(unsafe { std::slice::from_raw_parts(hash_ptr, FELT_LEN) });
    let k = slice_to_felt(unsafe { std::slice::from_raw_parts(k_ptr, FELT_LEN) });
    match sign(&priv_key, &hash, &k) {
        Ok(sig) => {
            copy_felt_to(sig.r, r_out_ptr);
            copy_felt_to(sig.s, s_out_ptr);
            0
        }
        Err(SignError::InvalidMessageHash) => 1,
        Err(SignError::InvalidK) => 2,
    }
}

/// Get public key from private key. priv_key 32 bytes LE, writes 32 bytes LE to out_ptr.
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn starknet_crypto_public_key(priv_key_ptr: *const u8, out_ptr: *mut u8) -> i32 {
    if priv_key_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let priv_key = slice_to_felt(unsafe { std::slice::from_raw_parts(priv_key_ptr, FELT_LEN) });
    let pub_key = get_public_key(&priv_key);
    copy_felt_to(pub_key, out_ptr);
    0
}

/// Verify ECDSA signature. All inputs 32 bytes LE.
/// Returns: 0 = invalid signature, 1 = valid, 2 = verification error (e.g. invalid key).
#[no_mangle]
pub extern "C" fn starknet_crypto_verify(
    pub_key_ptr: *const u8,
    hash_ptr: *const u8,
    r_ptr: *const u8,
    s_ptr: *const u8,
) -> i32 {
    if pub_key_ptr.is_null() || hash_ptr.is_null() || r_ptr.is_null() || s_ptr.is_null() {
        return -1;
    }
    let pub_key = slice_to_felt(unsafe { std::slice::from_raw_parts(pub_key_ptr, FELT_LEN) });
    let hash = slice_to_felt(unsafe { std::slice::from_raw_parts(hash_ptr, FELT_LEN) });
    let r = slice_to_felt(unsafe { std::slice::from_raw_parts(r_ptr, FELT_LEN) });
    let s = slice_to_felt(unsafe { std::slice::from_raw_parts(s_ptr, FELT_LEN) });
    match verify(&pub_key, &hash, &r, &s) {
        Ok(valid) => if valid { 1 } else { 0 },
        Err(_) => 2,
    }
}

/// RFC 6979 deterministic k. message_hash and private_key 32 bytes LE.
/// seed_ptr may be null; if non-null, seed_len must be 32 (optional extra entropy).
/// Writes k (32 bytes LE) to out_ptr. Returns 0 on success.
#[no_mangle]
pub extern "C" fn starknet_crypto_rfc6979_nonce(
    hash_ptr: *const u8,
    priv_key_ptr: *const u8,
    seed_ptr: *const u8,
    seed_len: usize,
    out_ptr: *mut u8,
) -> i32 {
    if hash_ptr.is_null() || priv_key_ptr.is_null() || out_ptr.is_null() {
        return -1;
    }
    let hash = slice_to_felt(unsafe { std::slice::from_raw_parts(hash_ptr, FELT_LEN) });
    let priv_key = slice_to_felt(unsafe { std::slice::from_raw_parts(priv_key_ptr, FELT_LEN) });
    let seed = if seed_ptr.is_null() || seed_len == 0 {
        None
    } else if seed_len >= FELT_LEN {
        let s = slice_to_felt(unsafe { std::slice::from_raw_parts(seed_ptr, FELT_LEN) });
        Some(s)
    } else {
        return -2;
    };
    let k = rfc6979_generate_k(&hash, &priv_key, seed.as_ref());
    copy_felt_to(k, out_ptr);
    0
}

fn slice_to_felt(s: &[u8]) -> Felt {
    let arr: [u8; FELT_LEN] = s.try_into().unwrap_or([0u8; FELT_LEN]);
    Felt::from_bytes_le_slice(&arr)
}

fn copy_felt_to(f: Felt, out: *mut u8) {
    let bytes = f.to_bytes_le();
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, FELT_LEN);
    }
}
