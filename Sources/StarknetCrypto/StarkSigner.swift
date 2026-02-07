import Foundation
import StarknetCryptoFFI

/// Stark curve ECDSA sign / verify and public key derivation. All values 32-byte little-endian.
public enum StarkSigner {
    /// Compute public key from private key. Returns 32-byte public key (LE).
    public static func publicKey(privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else {
            throw StarknetCryptoError.invalidInput
        }
        var out = Data(count: 32)
        let code = privateKey.withUnsafeBytes { pkRaw in
            out.withUnsafeMutableBytes { outRaw in
                starknet_crypto_public_key(
                    pkRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    outRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        if code != 0 {
            throw StarknetCryptoError.invalidInput
        }
        return out
    }

    /// ECDSA sign message hash with given k. Returns (r, s) as 32-byte Data each.
    public static func sign(privateKey: Data, hash: Data, k: Data) throws -> (r: Data, s: Data) {
        guard privateKey.count == 32, hash.count == 32, k.count == 32 else {
            throw StarknetCryptoError.invalidInput
        }
        var rOut = Data(count: 32)
        var sOut = Data(count: 32)
        let code = privateKey.withUnsafeBytes { pkRaw in
            hash.withUnsafeBytes { hRaw in
                k.withUnsafeBytes { kRaw in
                    rOut.withUnsafeMutableBytes { rRaw in
                        sOut.withUnsafeMutableBytes { sRaw in
                            starknet_crypto_sign(
                                pkRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                hRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                kRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                rRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                sRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        }
        switch code {
        case 0:
            return (rOut, sOut)
        case 1:
            throw StarknetCryptoError.invalidMessageHash
        case 2:
            throw StarknetCryptoError.invalidK
        default:
            throw StarknetCryptoError.invalidInput
        }
    }

    /// Verify ECDSA signature. Returns true if valid.
    public static func verify(publicKey: Data, hash: Data, r: Data, s: Data) throws -> Bool {
        guard publicKey.count == 32, hash.count == 32, r.count == 32, s.count == 32 else {
            throw StarknetCryptoError.invalidInput
        }
        let code = publicKey.withUnsafeBytes { pkRaw in
            hash.withUnsafeBytes { hRaw in
                r.withUnsafeBytes { rRaw in
                    s.withUnsafeBytes { sRaw in
                        starknet_crypto_verify(
                            pkRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            hRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            rRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            sRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        switch code {
        case 0:
            return false
        case 1:
            return true
        case 2:
            throw StarknetCryptoError.verifyError
        default:
            throw StarknetCryptoError.invalidInput
        }
    }

    /// RFC 6979 deterministic k from message hash and private key. Optional seed (32 bytes) for extra entropy.
    public static func rfc6979Nonce(messageHash: Data, privateKey: Data, seed: Data?) throws -> Data {
        guard messageHash.count == 32, privateKey.count == 32 else {
            throw StarknetCryptoError.invalidInput
        }
        if let seed = seed, seed.count != 0 && seed.count != 32 {
            throw StarknetCryptoError.invalidSeedLength
        }
        var kOut = Data(count: 32)
        let code: Int32
        if let seed = seed, seed.count == 32 {
            code = messageHash.withUnsafeBytes { hRaw in
                privateKey.withUnsafeBytes { pkRaw in
                    seed.withUnsafeBytes { seedRaw in
                        kOut.withUnsafeMutableBytes { outRaw in
                            starknet_crypto_rfc6979_nonce(
                                hRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                pkRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                seedRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                32,
                                outRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                            )
                        }
                    }
                }
            }
        } else {
            code = messageHash.withUnsafeBytes { hRaw in
                privateKey.withUnsafeBytes { pkRaw in
                    kOut.withUnsafeMutableBytes { outRaw in
                        starknet_crypto_rfc6979_nonce(
                            hRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            pkRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            nil,
                            0,
                            outRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                        )
                    }
                }
            }
        }
        if code != 0 {
            if code == -2 {
                throw StarknetCryptoError.invalidSeedLength
            }
            throw StarknetCryptoError.invalidInput
        }
        return kOut
    }
}
