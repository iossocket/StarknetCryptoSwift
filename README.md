# StarknetCryptoSwift

[![Tests](https://github.com/iossocket/StarknetCryptoSwift/actions/workflows/ci.yml/badge.svg)](https://github.com/iossocket/StarknetCryptoSwift/actions/workflows/ci.yml)

A standalone Swift Package Manager (SPM) package that exposes Starknet crypto (Pedersen, Poseidon, Stark curve ECDSA, RFC 6979) via Swift. The implementation is based on [starknet-rs](https://github.com/xJonathanLEI/starknet-rs) `starknet-crypto`.

## Features

| Capability               | Swift API                                                           | Description                                      |
| ------------------------ | ------------------------------------------------------------------- | ------------------------------------------------ |
| Pedersen Hash            | `PedersenHash.hash(_:_:)`                                           | Two 32-byte (LE) inputs → 32 bytes               |
| Poseidon Hash            | `PoseidonHash.hash(_:_:)` / `PoseidonHash.hash(_:)`                 | Multiple Felts → single Felt (Hades)             |
| Stark curve ECDSA        | `StarkSigner.sign` / `StarkSigner.verify` / `StarkSigner.publicKey` | Sign, verify, public key derivation              |
| RFC 6979 deterministic k | `StarkSigner.rfc6979Nonce(messageHash:privateKey:seed:)`            | Derive k from hash + private key + optional seed |

All inputs and outputs are **32-byte little-endian** (Starknet Felt representation).

## Adding as a dependency

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/your-username/StarknetCryptoSwift.git", from: "0.1.0"),
],
targets: [
    .target(name: "YourTarget", dependencies: ["StarknetCrypto"]),
]
```

```swift
import StarknetCrypto

// Pedersen
let hash = try PedersenHash.hash(a, b)  // Data, Data -> Data

// Poseidon
let h2 = try PoseidonHash.hash(a, b)
let hN = try PoseidonHash.hash([felt1, felt2, felt3])

// Public key / sign / verify
let pub = try StarkSigner.publicKey(privateKey: privateKey)
let k = try StarkSigner.rfc6979Nonce(messageHash: hash, privateKey: privateKey, seed: nil)
let (r, s) = try StarkSigner.sign(privateKey: privateKey, hash: hash, k: k)
let valid = try StarkSigner.verify(publicKey: pub, hash: hash, r: r, s: s)
```

## Building the xcframework (maintainers / CI)

The package uses a **binaryTarget** pointing at a prebuilt `StarknetCrypto.xcframework`. Build it after cloning or before cutting a new release:

1. Install Rust and set the default toolchain:  
   `rustup default stable`
2. Add iOS/macOS targets:  
   `rustup target add aarch64-apple-ios aarch64-apple-ios-simulator x86_64-apple-ios-simulator aarch64-apple-darwin x86_64-apple-darwin`
3. From the repository root, run:  
   `./scripts/build_xcframework.sh`

The script produces `XCFrameworks/StarknetCrypto.xcframework` (iOS device, iOS simulator, and macOS multi-arch). If this directory already exists in the repo, it may only contain the macos-arm64 slice (for local development); run the script in a Rust-enabled environment to get full iOS and macOS support. You can commit the full xcframework or have CI build it and publish a Release zip, then point `Package.swift`’s `binaryTarget` at the URL and checksum.

## Requirements

- **Swift** 5.9+
- **iOS** 13+ (device + simulator), **macOS** 10.15+
- Compatible with Starknet; implementation aligned with starknet-rs

## Repository layout

```
StarknetCryptoSwift/
├── Package.swift
├── Sources/StarknetCrypto/     # Swift wrapper
├── Rust/                       # FFI implementation (starknet-crypto)
├── XCFrameworks/               # Prebuilt xcframework (run script to generate)
├── scripts/build_xcframework.sh
└── Tests/StarknetCryptoTests/
```

## Testing

**Rust** (requires Rust: `rustup default stable`):

```bash
cd Rust && cargo test
```

- `tests/pedersen_test.rs`: Pedersen FFI matches `starknet_crypto::pedersen_hash`; null pointer returns error.
- `tests/poseidon_test.rs`: Poseidon hash_2 / hash_many match the library; null/empty input errors.
- `tests/ecdsa_test.rs`: Public key, RFC 6979, sign/verify match `starknet_crypto`; null pointer errors.

**Swift** (requires a built xcframework):

```bash
swift test
```

## Versioning and protocol

- Follows semantic versioning; when the Starknet protocol changes, we evaluate upgrading starknet-rs and release a new minor.
- This package does not depend on StarknetKit and uses only `Data` (32 bytes); callers handle conversion to/from StarknetKit’s `Felt` if needed.
