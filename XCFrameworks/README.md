# XCFrameworks

This directory holds the built `StarknetCrypto.xcframework`.

## When to update

Rebuild and update the xcframework whenever any of the following change:

- **Rust code** in `Rust/src/` (Pedersen, Poseidon, ECDSA FFI, or dependencies)
- **`Rust/Cargo.toml`** (e.g. `starknet-crypto` version or crate config)
- **C API / headers** in `Rust/StarknetCryptoFFI.h` or `Rust/module.modulemap`
- **Supported platforms or architectures** (if you change `scripts/build_xcframework.sh` targets)

You do **not** need to rebuild when only Swift code in `Sources/StarknetCrypto/` or tests change.

## How to build

From the repository root, run:

```bash
./scripts/build_xcframework.sh
```

You need Rust installed (`rustup default stable`) and the iOS/macOS targets. After building, you can commit this directory or have CI build and attach it to a Release.
