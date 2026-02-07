//! FFI tests for ECDSA: sign, verify, public key, RFC 6979.
//!
//! Strategy: Compare FFI results with `starknet_crypto` and test return codes for
//! success, invalid signature, and error paths (null, InvalidMessageHash, InvalidK).

use starknet_crypto_ffi::{
    starknet_crypto_public_key,
    starknet_crypto_rfc6979_nonce,
    starknet_crypto_sign,
    starknet_crypto_verify,
};
use starknet_crypto::{get_public_key, rfc6979_generate_k, sign, verify, Felt};

const FELT_LEN: usize = 32;

fn felt_to_le_bytes(f: &Felt) -> [u8; FELT_LEN] {
    f.to_bytes_le()
}

#[test]
fn public_key_ffi_matches_starknet_crypto() {
    let priv_key = Felt::from(1u64);
    let expected = get_public_key(&priv_key);
    let expected_bytes = felt_to_le_bytes(&expected);

    let priv_bytes = felt_to_le_bytes(&priv_key);
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_public_key(priv_bytes.as_ptr(), out.as_mut_ptr());
    assert_eq!(code, 0);
    assert_eq!(out, expected_bytes);
}

#[test]
fn rfc6979_nonce_ffi_matches_starknet_crypto() {
    let hash = Felt::from(0x42u64);
    let priv_key = Felt::from(1u64);
    let expected = rfc6979_generate_k(&hash, &priv_key, None);
    let expected_bytes = felt_to_le_bytes(&expected);

    let hash_bytes = felt_to_le_bytes(&hash);
    let priv_bytes = felt_to_le_bytes(&priv_key);
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_rfc6979_nonce(
        hash_bytes.as_ptr(),
        priv_bytes.as_ptr(),
        std::ptr::null(),
        0,
        out.as_mut_ptr(),
    );
    assert_eq!(code, 0);
    assert_eq!(out, expected_bytes);
}

#[test]
fn sign_then_verify_roundtrip() {
    let priv_key = Felt::from(0x1234u64);
    let message = Felt::from(0xabcdu64);
    let k = rfc6979_generate_k(&message, &priv_key, None);

    let sig = sign(&priv_key, &message, &k).expect("sign should succeed");
    let r_bytes = felt_to_le_bytes(&sig.r);
    let s_bytes = felt_to_le_bytes(&sig.s);

    // FFI sign
    let priv_bytes = felt_to_le_bytes(&priv_key);
    let msg_bytes = felt_to_le_bytes(&message);
    let k_bytes = felt_to_le_bytes(&k);
    let mut r_out = [0u8; FELT_LEN];
    let mut s_out = [0u8; FELT_LEN];
    let code = starknet_crypto_sign(
        priv_bytes.as_ptr(),
        msg_bytes.as_ptr(),
        k_bytes.as_ptr(),
        r_out.as_mut_ptr(),
        s_out.as_mut_ptr(),
    );
    assert_eq!(code, 0);
    assert_eq!(r_out, r_bytes);
    assert_eq!(s_out, s_bytes);

    // Verify with starknet_crypto
    let pub_key = get_public_key(&priv_key);
    let valid = verify(&pub_key, &message, &sig.r, &sig.s).expect("verify should not error");
    assert!(valid);

    // Verify via FFI
    let pub_bytes = felt_to_le_bytes(&pub_key);
    let code = starknet_crypto_verify(
        pub_bytes.as_ptr(),
        msg_bytes.as_ptr(),
        r_out.as_ptr(),
        s_out.as_ptr(),
    );
    assert_eq!(code, 1, "FFI verify should return 1 (valid)");
}

/// Valid public key + wrong (r, s) must return 0 (invalid signature), not 1.
#[test]
fn verify_wrong_signature_returns_zero() {
    let priv_key = Felt::from(0x1234u64);
    let pub_key = get_public_key(&priv_key);
    let message = Felt::from(0xabcdu64);
    let pub_bytes = felt_to_le_bytes(&pub_key);
    let msg_bytes = felt_to_le_bytes(&message);
    // Wrong (r, s): not the signature of (priv_key, message)
    let wrong_r = felt_to_le_bytes(&Felt::from(1u64));
    let wrong_s = felt_to_le_bytes(&Felt::from(2u64));
    let code = starknet_crypto_verify(
        pub_bytes.as_ptr(),
        msg_bytes.as_ptr(),
        wrong_r.as_ptr(),
        wrong_s.as_ptr(),
    );
    assert_eq!(code, 0, "wrong (r,s) must yield 0 (invalid signature)");
}

/// RFC 6979 with optional seed: FFI result must match starknet_crypto.
#[test]
fn rfc6979_with_seed_ffi_matches_starknet_crypto() {
    let hash = Felt::from(0xdeadbeefu64);
    let priv_key = Felt::from(0xbeefu64);
    let seed = Felt::from(0x1234u64);
    let expected = rfc6979_generate_k(&hash, &priv_key, Some(&seed));
    let expected_bytes = felt_to_le_bytes(&expected);

    let hash_bytes = felt_to_le_bytes(&hash);
    let priv_bytes = felt_to_le_bytes(&priv_key);
    let seed_bytes = felt_to_le_bytes(&seed);
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_rfc6979_nonce(
        hash_bytes.as_ptr(),
        priv_bytes.as_ptr(),
        seed_bytes.as_ptr(),
        FELT_LEN,
        out.as_mut_ptr(),
    );
    assert_eq!(code, 0);
    assert_eq!(out, expected_bytes);
}

/// Sign with invalid k (e.g. 0): FFI must not return 0 (success); should return 2 (InvalidK).
#[test]
fn sign_invalid_k_returns_error_code() {
    let priv_key = felt_to_le_bytes(&Felt::from(0x1234u64));
    let message = felt_to_le_bytes(&Felt::from(0xabcdu64));
    let k_zero = [0u8; FELT_LEN];
    let mut r_out = [0u8; FELT_LEN];
    let mut s_out = [0u8; FELT_LEN];
    let code = starknet_crypto_sign(
        priv_key.as_ptr(),
        message.as_ptr(),
        k_zero.as_ptr(),
        r_out.as_mut_ptr(),
        s_out.as_mut_ptr(),
    );
    assert_ne!(code, 0, "k=0 must not succeed");
    assert_eq!(code, 2, "starknet_crypto returns InvalidK (2) for k=0");
}

/// Sign with null pointer should return -1.
#[test]
fn sign_null_ptr_returns_error() {
    let buf = [0u8; FELT_LEN];
    let mut r_out = [0u8; FELT_LEN];
    let mut s_out = [0u8; FELT_LEN];
    assert_eq!(
        starknet_crypto_sign(
            std::ptr::null(),
            buf.as_ptr(),
            buf.as_ptr(),
            r_out.as_mut_ptr(),
            s_out.as_mut_ptr(),
        ),
        -1
    );
}

#[test]
fn ecdsa_ffi_null_returns_error() {
    let buf = [0u8; FELT_LEN];
    let mut out = [0u8; FELT_LEN];
    assert_eq!(starknet_crypto_public_key(std::ptr::null(), out.as_mut_ptr()), -1);
    assert_eq!(starknet_crypto_public_key(buf.as_ptr(), std::ptr::null_mut()), -1);

    assert_eq!(
        starknet_crypto_rfc6979_nonce(
            std::ptr::null(),
            buf.as_ptr(),
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
        ),
        -1
    );
    assert_eq!(
        starknet_crypto_rfc6979_nonce(
            buf.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
        ),
        -1
    );
}

/// seed_ptr non-null but seed_len in (1..32) must return -2.
#[test]
fn rfc6979_invalid_seed_len_returns_error() {
    let hash = [0u8; FELT_LEN];
    let priv_key = [0u8; FELT_LEN];
    let seed_short = [0u8; 16];
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_rfc6979_nonce(
        hash.as_ptr(),
        priv_key.as_ptr(),
        seed_short.as_ptr(),
        16,
        out.as_mut_ptr(),
    );
    assert_eq!(code, -2);
}
