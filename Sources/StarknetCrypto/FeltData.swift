import Foundation

/// Helpers for 32-byte Felt and `Data` conversion. Starknet uses little-endian 32-byte representation.
public enum FeltData {
    /// Expected Felt byte length.
    public static let feltByteCount = 32

    /// Convert `Data` to fixed 32-byte Felt representation (little-endian). Pads or truncates as needed.
    /// - Parameter data: Up to 32 bytes; if shorter, zero-padded on the right (LE: high bytes zero).
    public static func dataToFelt(_ data: Data) -> Data {
        var bytes = [UInt8](data.prefix(feltByteCount))
        while bytes.count < feltByteCount {
            bytes.append(0)
        }
        return Data(bytes)
    }

    /// Ensure data is exactly 32 bytes (e.g. for hashing). Returns nil if length is not 32.
    public static func require32(_ data: Data) -> Data? {
        data.count == feltByteCount ? data : nil
    }
}
