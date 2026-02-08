import Testing
import Foundation
@testable import StarknetCrypto

@Suite("PoseidonHash")
struct PoseidonHashTests {
    static let valid32 = Data(repeating: 0, count: 32)

    @Test("hashDirect two Felts determinism")
    func hashDirectDeterminism() throws {
        let a = Data(repeating: 1, count: 32)
        let b = Data(repeating: 2, count: 32)
        let h1 = try PoseidonHash.hashDirect(a, b)
        let h2 = try PoseidonHash.hashDirect(a, b)
        #expect(h1 == h2)
        #expect(h1.count == 32)
    }

    @Test("hashSingle determinism")
    func hashSingleDeterminism() throws {
        let v = Data(repeating: 42, count: 32)
        let h1 = try PoseidonHash.hashSingle(v)
        let h2 = try PoseidonHash.hashSingle(v)
        #expect(h1 == h2)
        #expect(h1.count == 32)
    }

    @Test("Hash two Felts determinism")
    func determinism() throws {
        let a = Data(repeating: 1, count: 32)
        let b = Data(repeating: 2, count: 32)
        let h1 = try PoseidonHash.hash(a, b)
        let h2 = try PoseidonHash.hash(a, b)
        #expect(h1 == h2)
        #expect(h1.count == 32)
    }

    @Test("Hash many elements")
    func hashMany() throws {
        let el1 = Data(repeating: 1, count: 32)
        let el2 = Data(repeating: 2, count: 32)
        let el3 = Data(repeating: 3, count: 32)
        let h = try PoseidonHash.hash([el1, el2, el3])
        #expect(h.count == 32)
    }

    @Test("Hash single element")
    func hashSingle() throws {
        let el = Data(repeating: 42, count: 32)
        let h = try PoseidonHash.hash([el])
        #expect(h.count == 32)
    }

    @Test("Empty elements throws")
    func emptyThrows() {
        #expect(throws: StarknetCryptoError.self) {
            _ = try PoseidonHash.hash([])
        }
    }

    @Test("Element with wrong length in hash(_:) throws")
    func wrongLengthElementThrows() {
        let short = Data(repeating: 0, count: 16)
        let valid = Data(repeating: 1, count: 32)
        #expect(throws: StarknetCryptoError.self) {
            _ = try PoseidonHash.hash([valid, short])
        }
    }
}
