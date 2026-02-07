import Testing
import Foundation
@testable import StarknetCrypto

@Suite("PedersenHash")
struct PedersenHashTests {
    static let zero32 = Data(count: 32)
    static let valid32 = Data(repeating: 1, count: 32)

    @Test("Hash determinism: same input gives same output")
    func determinism() throws {
        let a = Data(repeating: 1, count: 32)
        let b = Data(repeating: 2, count: 32)
        let h1 = try PedersenHash.hash(a, b)
        let h2 = try PedersenHash.hash(a, b)
        #expect(h1 == h2)
        #expect(h1.count == 32)
    }

    @Test("Hash(0,0) produces 32-byte output")
    func zeroZero() throws {
        let h = try PedersenHash.hash(Self.zero32, Self.zero32)
        #expect(h.count == 32)
    }

    @Test("First argument wrong length throws invalidHashInput")
    func invalidFirstInput() {
        let short = Data(repeating: 0, count: 16)
        #expect(throws: StarknetCryptoError.self) {
            _ = try PedersenHash.hash(short, Self.valid32)
        }
    }

    @Test("Second argument wrong length throws invalidHashInput")
    func invalidSecondInput() {
        let short = Data(repeating: 0, count: 16)
        #expect(throws: StarknetCryptoError.self) {
            _ = try PedersenHash.hash(Self.valid32, short)
        }
    }
}
