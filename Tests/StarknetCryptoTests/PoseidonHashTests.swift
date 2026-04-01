import Testing
import Foundation
@testable import StarknetCrypto

@Suite("PoseidonHash")
struct PoseidonHashTests {
    static let valid32 = Data(repeating: 0, count: 32)
    
    private func feltHex(_ littleEndianData: Data) -> String {
        let full = littleEndianData.reversed().map { String(format: "%02x", $0) }.joined()
        let trimmed = full.drop(while: { $0 == "0" })
        return "0x" + (trimmed.isEmpty ? "0" : String(trimmed))
    }

    private func feltData(_ value: UInt64) -> Data {
        var data = Data(repeating: 0, count: 32)
        var v = value
        for i in 0..<8 {
            data[i] = UInt8(v & 0xff)
            v >>= 8
        }
        return data
    }

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

    @Test("Hash empty matches Starknet.js vector")
    func emptyHashMatchesStarknetJs() throws {
        let empty = try PoseidonHash.hash([])
        #expect(feltHex(empty) == "0x2272be0f580fd156823304800919530eaa97430e972d7213ee13f4fbf7a5dbc")
    }
    
    @Test("Hash empty is different from hash([0])")
    func emptyDifferentFromSingleZero() throws {
        let empty = try PoseidonHash.hash([])
        let zero = try PoseidonHash.hash([Data(repeating: 0, count: 32)])
        #expect(empty != zero)
        #expect(feltHex(zero) == "0x545d6f7d28a8a398e543948be5a026af60c4dea482867a6eeb2525b35d1e1e1")
    }
    
    @Test("Starknet.js vector: hashSingle(0)")
    func hashSingleZeroVector() throws {
        let h = try PoseidonHash.hashSingle(Data(repeating: 0, count: 32))
        #expect(feltHex(h) == "0x60009f680a43e6f760790f76214b26243464cdd4f31fdc460baf66d32897c1b")
    }
    
    @Test("Starknet.js vector: hashSingle(1)")
    func hashSingleOneVector() throws {
        let h = try PoseidonHash.hashSingle(feltData(1))
        #expect(feltHex(h) == "0x6d226d4c804cd74567f5ac59c6a4af1fe2a6eced19fb7560a9124579877da25")
    }
    
    @Test("Starknet.js vector: hashDirect(0,0)")
    func hashDirectZeroZeroVector() throws {
        let zero = Data(repeating: 0, count: 32)
        let h = try PoseidonHash.hashDirect(zero, zero)
        #expect(feltHex(h) == "0x293d3e8a80f400daaaffdd5932e2bcc8814bab8f414a75dcacf87318f8b14c5")
    }
    
    @Test("Starknet.js vector: hashMany([0,0,0])")
    func hashManyThreeZerosVector() throws {
        let zero = Data(repeating: 0, count: 32)
        let h = try PoseidonHash.hash([zero, zero, zero])
        #expect(feltHex(h) == "0x29aee7812642221479b7e8af204ceaa5a7b7e113349fc8fb93e6303b477eb4d")
    }
    
    @Test("Starknet.js vector: hashMany([10,8,5])")
    func hashManySmallValuesVector() throws {
        let h = try PoseidonHash.hash([feltData(10), feltData(8), feltData(5)])
        #expect(feltHex(h) == "0x53aa661c2388b74f48a16163c38893760e26884211599194ffe264f14b5c6e7")
    }
    
    @Test("Starknet.js vector: hashMany([0,0,0,0])")
    func hashManyFourZerosVector() throws {
        let zero = Data(repeating: 0, count: 32)
        let h = try PoseidonHash.hash([zero, zero, zero, zero])
        #expect(feltHex(h) == "0x5c4def9d0323f31f80e90c55fa780591ed2e2fee266491c0bd891aedac38935")
    }
    
    @Test("Starknet.js vector: hashMany([1,10,100,1000])")
    func hashManyFourValuesVector() throws {
        let h = try PoseidonHash.hash([feltData(1), feltData(10), feltData(100), feltData(1000)])
        #expect(feltHex(h) == "0x51f923f87ee53d16c2d680c2c0c9eb0132ba255d52b6dd69f4b9918dcbe00a1")
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
