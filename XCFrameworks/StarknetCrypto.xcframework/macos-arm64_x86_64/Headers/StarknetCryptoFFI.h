#ifndef StarknetCryptoFFI_h
#define StarknetCryptoFFI_h

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/// All buffers are 32 bytes, little-endian (Starknet Felt representation).

/// Pedersen hash of two Felts. Returns 0 on success, -1 on null/invalid args.
int32_t starknet_crypto_pedersen_hash(const uint8_t *a_ptr, const uint8_t *b_ptr, uint8_t *out_ptr);

/// Poseidon hash of two Felts. Returns 0 on success, -1 on null/invalid args.
int32_t starknet_crypto_poseidon_hash_2(const uint8_t *a_ptr, const uint8_t *b_ptr, uint8_t *out_ptr);

/// Poseidon hash of many Felts. inputs_ptr points to count*32 bytes (LE). Returns 0 on success, -1 null, -2 count 0.
int32_t starknet_crypto_poseidon_hash_many(const uint8_t *inputs_ptr, size_t count, uint8_t *out_ptr);

/// ECDSA sign. Returns 0 = success, 1 = InvalidMessageHash, 2 = InvalidK, -1 = null/invalid args.
int32_t starknet_crypto_sign(
    const uint8_t *priv_key_ptr,
    const uint8_t *hash_ptr,
    const uint8_t *k_ptr,
    uint8_t *r_out_ptr,
    uint8_t *s_out_ptr
);

/// Public key from private key. Returns 0 on success, -1 on null.
int32_t starknet_crypto_public_key(const uint8_t *priv_key_ptr, uint8_t *out_ptr);

/// Verify ECDSA signature. Returns 0 = invalid sig, 1 = valid, 2 = verify error, -1 = null.
int32_t starknet_crypto_verify(
    const uint8_t *pub_key_ptr,
    const uint8_t *hash_ptr,
    const uint8_t *r_ptr,
    const uint8_t *s_ptr
);

/// RFC 6979 deterministic k. seed_ptr may be null; if non-null, seed_len must be 32. Returns 0 success, -1 null, -2 invalid seed_len.
int32_t starknet_crypto_rfc6979_nonce(
    const uint8_t *hash_ptr,
    const uint8_t *priv_key_ptr,
    const uint8_t *seed_ptr,
    size_t seed_len,
    uint8_t *out_ptr
);

#ifdef __cplusplus
}
#endif

#endif /* StarknetCryptoFFI_h */
