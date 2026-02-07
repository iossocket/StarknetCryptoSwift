import Foundation
import StarknetCryptoFFI

/// Starknet Pedersen hash. All inputs and outputs are 32-byte little-endian (Felt representation).
public enum PedersenHash {
    /// Hash two 32-byte Felts. Returns 32-byte hash (LE).
    /// - Throws: `StarknetCryptoError.invalidHashInput` if either input is not 32 bytes.
    public static func hash(_ a: Data, _ b: Data) throws -> Data {
        guard a.count == 32, b.count == 32 else {
            throw StarknetCryptoError.invalidHashInput
        }
        var out = Data(count: 32)
        let code = a.withUnsafeBytes { aRaw in
            b.withUnsafeBytes { bRaw in
                out.withUnsafeMutableBytes { outRaw in
                    starknet_crypto_pedersen_hash(
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
}
