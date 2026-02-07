import Foundation

/// Errors thrown by Starknet crypto operations.
public enum StarknetCryptoError: Error {
    /// Invalid or null pointer / invalid buffer (internal FFI error).
    case invalidInput
    /// Pedersen/Poseidon hash received invalid or wrong-length input.
    case invalidHashInput
    /// ECDSA sign: invalid message hash.
    case invalidMessageHash
    /// ECDSA sign: invalid k value.
    case invalidK
    /// ECDSA verify: invalid public key or other verification error.
    case verifyError
    /// RFC 6979: invalid seed length (must be 0 or 32).
    case invalidSeedLength
}
