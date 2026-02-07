//! FFI tests for Poseidon hash.
//!
//! Strategy: Compare FFI output with `starknet_crypto::poseidon_hash_many` so the FFI layer
//! matches the library. Covers hash_2, hash_many (multiple and single element), and error paths.

use starknet_crypto_ffi::{starknet_crypto_poseidon_hash_2, starknet_crypto_poseidon_hash_many};
use starknet_crypto::poseidon_hash_many;
use starknet_crypto::Felt;

const FELT_LEN: usize = 32;

fn felt_to_le_bytes(f: &Felt) -> [u8; FELT_LEN] {
    f.to_bytes_le()
}

#[test]
fn poseidon_hash_2_ffi_matches_starknet_crypto() {
    let cases: [(Felt, Felt); 3] = [
        (Felt::from(0u64), Felt::from(0u64)),
        (Felt::from(1u64), Felt::from(1u64)),
        (Felt::from(2u64), Felt::from(3u64)),
    ];
    for (a, b) in cases {
        let expected = poseidon_hash_many([&a, &b]);
        let expected_bytes = felt_to_le_bytes(&expected);

        let a_bytes = felt_to_le_bytes(&a);
        let b_bytes = felt_to_le_bytes(&b);
        let mut out = [0u8; FELT_LEN];
        let code = starknet_crypto_poseidon_hash_2(
            a_bytes.as_ptr(),
            b_bytes.as_ptr(),
            out.as_mut_ptr(),
        );
        assert_eq!(code, 0);
        assert_eq!(out, expected_bytes);
    }
}

#[test]
fn poseidon_hash_many_ffi_matches_starknet_crypto() {
    let felts = [Felt::from(0u64), Felt::from(1u64), Felt::from(2u64)];
    let refs: Vec<&Felt> = felts.iter().collect();
    let expected = poseidon_hash_many(refs);
    let expected_bytes = felt_to_le_bytes(&expected);

    let mut input_bytes = Vec::with_capacity(felts.len() * FELT_LEN);
    for f in &felts {
        input_bytes.extend_from_slice(&felt_to_le_bytes(f));
    }
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_poseidon_hash_many(
        input_bytes.as_ptr(),
        felts.len(),
        out.as_mut_ptr(),
    );
    assert_eq!(code, 0);
    assert_eq!(out, expected_bytes);
}

#[test]
fn poseidon_hash_many_single_element() {
    let f = Felt::from(42u64);
    let expected = poseidon_hash_many([&f]);
    let expected_bytes = felt_to_le_bytes(&expected);
    let input = felt_to_le_bytes(&f);
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_poseidon_hash_many(input.as_ptr(), 1, out.as_mut_ptr());
    assert_eq!(code, 0);
    assert_eq!(out, expected_bytes);
}

#[test]
fn poseidon_hash_many_empty_returns_error() {
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_poseidon_hash_many(
        [0u8; FELT_LEN].as_ptr(),
        0,
        out.as_mut_ptr(),
    );
    assert_eq!(code, -2);
}

#[test]
fn poseidon_ffi_null_input_returns_error() {
    let a = [0u8; FELT_LEN];
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_poseidon_hash_2(std::ptr::null(), a.as_ptr(), out.as_mut_ptr());
    assert_eq!(code, -1);
}
