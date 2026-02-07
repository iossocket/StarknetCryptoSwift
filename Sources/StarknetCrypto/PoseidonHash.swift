import Foundation
import StarknetCryptoFFI

/// Starknet Poseidon hash (Hades permutation). Inputs and output are 32-byte little-endian Felts.
public enum PoseidonHash {
    /// Hash two 32-byte Felts. Returns 32-byte hash (LE).
    public static func hash(_ a: Data, _ b: Data) throws -> Data {
        guard a.count == 32, b.count == 32 else {
            throw StarknetCryptoError.invalidHashInput
        }
        var out = Data(count: 32)
        let code = a.withUnsafeBytes { aRaw in
            b.withUnsafeBytes { bRaw in
                out.withUnsafeMutableBytes { outRaw in
                    starknet_crypto_poseidon_hash_2(
                        aRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        bRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        outRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }
        if code != 0 {
            throw StarknetCryptoError.invalidInput
        }
        return out
    }

    /// Hash an arbitrary number of 32-byte Felts. Returns single 32-byte Felt (LE).
    public static func hash(_ elements: [Data]) throws -> Data {
        for el in elements {
            guard el.count == 32 else {
                throw StarknetCryptoError.invalidHashInput
            }
        }
        guard !elements.isEmpty else {
            throw StarknetCryptoError.invalidHashInput
        }
        var contiguous = Data()
        for el in elements {
            contiguous.append(el)
        }
        var out = Data(count: 32)
        let code = contiguous.withUnsafeBytes { inputsRaw in
            out.withUnsafeMutableBytes { outRaw in
                starknet_crypto_poseidon_hash_many(
                    inputsRaw.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    elements.count,
                    outRaw.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
        if code != 0 {
            throw StarknetCryptoError.invalidInput
        }
        return out
    }
}
