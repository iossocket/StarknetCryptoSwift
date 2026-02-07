//! FFI tests for Pedersen hash.
//!
//! Strategy: Compare FFI output with `starknet_crypto::pedersen_hash` to ensure the FFI layer
//! matches the underlying library. For protocol compliance, align with Starknet / starknet-rs
//! test vectors when available.

use starknet_crypto_ffi::starknet_crypto_pedersen_hash;
use starknet_crypto::pedersen_hash;
use starknet_crypto::Felt;

const FELT_LEN: usize = 32;

fn felt_to_le_bytes(f: &Felt) -> [u8; FELT_LEN] {
    f.to_bytes_le()
}

#[test]
fn pedersen_ffi_matches_starknet_crypto() {
    let cases: [(Felt, Felt); 4] = [
        (Felt::from(0u64), Felt::from(0u64)),
        (Felt::from(1u64), Felt::from(1u64)),
        (Felt::from(2u64), Felt::from(2u64)),
        (Felt::from(0x1234_5678u64), Felt::from(0xabcd_ef00u64)),
    ];
    for (a, b) in cases {
        let expected = pedersen_hash(&a, &b);
        let expected_bytes = felt_to_le_bytes(&expected);

        let a_bytes = felt_to_le_bytes(&a);
        let b_bytes = felt_to_le_bytes(&b);
        let mut out = [0u8; FELT_LEN];
        let code = starknet_crypto_pedersen_hash(
            a_bytes.as_ptr(),
            b_bytes.as_ptr(),
            out.as_mut_ptr(),
        );
        assert_eq!(code, 0, "FFI should return 0");
        assert_eq!(out, expected_bytes, "FFI output should match starknet_crypto");
    }
}

/// Determinism: hashing the same inputs twice yields the same output.
#[test]
fn pedersen_deterministic() {
    let a = felt_to_le_bytes(&Felt::from(100u64));
    let b = felt_to_le_bytes(&Felt::from(200u64));
    let mut out1 = [0u8; FELT_LEN];
    let mut out2 = [0u8; FELT_LEN];
    assert_eq!(starknet_crypto_pedersen_hash(a.as_ptr(), b.as_ptr(), out1.as_mut_ptr()), 0);
    assert_eq!(starknet_crypto_pedersen_hash(a.as_ptr(), b.as_ptr(), out2.as_mut_ptr()), 0);
    assert_eq!(out1, out2);
}

#[test]
fn pedersen_ffi_null_input_returns_error() {
    let a = [0u8; FELT_LEN];
    let mut out = [0u8; FELT_LEN];
    let code = starknet_crypto_pedersen_hash(std::ptr::null(), a.as_ptr(), out.as_mut_ptr());
    assert_eq!(code, -1);
    let code = starknet_crypto_pedersen_hash(a.as_ptr(), std::ptr::null(), out.as_mut_ptr());
    assert_eq!(code, -1);
    let code = starknet_crypto_pedersen_hash(a.as_ptr(), a.as_ptr(), std::ptr::null_mut());
    assert_eq!(code, -1);
}
