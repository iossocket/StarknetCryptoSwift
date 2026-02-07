import Testing
import Foundation
@testable import StarknetCrypto

@Suite("StarkSigner")
struct StarkSignerTests {
    /// Fixed 32-byte private key (LE)
    static let privateKey: Data = {
        var d = Data(count: 32)
        d[0] = 1
        return d
    }()

    @Test("Public key derivation")
    func publicKey() throws {
        let pub = try StarkSigner.publicKey(privateKey: Self.privateKey)
        #expect(pub.count == 32)
    }

    @Test("Public key with wrong length throws")
    func publicKeyInvalidLength() {
        let short = Data(repeating: 0, count: 16)
        #expect(throws: StarknetCryptoError.self) {
            _ = try StarkSigner.publicKey(privateKey: short)
        }
    }

    @Test("RFC 6979 nonce deterministic")
    func rfc6979Deterministic() throws {
        let hash = Data(repeating: 0xab, count: 32)
        let k1 = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: Self.privateKey, seed: nil)
        let k2 = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: Self.privateKey, seed: nil)
        #expect(k1 == k2)
        #expect(k1.count == 32)
    }

    @Test("RFC 6979 with seed produces 32-byte k")
    func rfc6979WithSeed() throws {
        let hash = Data(repeating: 0xab, count: 32)
        let seed = Data(repeating: 0x11, count: 32)
        let k = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: Self.privateKey, seed: seed)
        #expect(k.count == 32)
    }

    @Test("RFC 6979 invalid seed length throws")
    func rfc6979InvalidSeedLength() {
        let hash = Data(repeating: 0, count: 32)
        let seedShort = Data(repeating: 0, count: 16)
        #expect(throws: StarknetCryptoError.self) {
            _ = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: Self.privateKey, seed: seedShort)
        }
    }

    @Test("Sign then verify round-trip")
    func signVerifyRoundTrip() throws {
        let hash = Data(repeating: 0x42, count: 32)
        let k = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: Self.privateKey, seed: nil)
        let (r, s) = try StarkSigner.sign(privateKey: Self.privateKey, hash: hash, k: k)
        #expect(r.count == 32)
        #expect(s.count == 32)
        let pub = try StarkSigner.publicKey(privateKey: Self.privateKey)
        let valid = try StarkSigner.verify(publicKey: pub, hash: hash, r: r, s: s)
        #expect(valid == true)
    }

    @Test("Verify returns false for wrong signature")
    func verifyWrongSignatureReturnsFalse() throws {
        let pub = try StarkSigner.publicKey(privateKey: Self.privateKey)
        let hash = Data(repeating: 0x42, count: 32)
        let wrongR = Data(repeating: 1, count: 32)
        let wrongS = Data(repeating: 2, count: 32)
        let valid = try StarkSigner.verify(publicKey: pub, hash: hash, r: wrongR, s: wrongS)
        #expect(valid == false)
    }

    @Test("Sign with invalid k throws invalidK")
    func signInvalidKThrows() {
        let hash = Data(repeating: 0x42, count: 32)
        let kZero = Data(count: 32)
        #expect(throws: StarknetCryptoError.self) {
            _ = try StarkSigner.sign(privateKey: Self.privateKey, hash: hash, k: kZero)
        }
    }
}
