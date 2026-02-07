#!/usr/bin/env bash
# Build Rust staticlib for iOS (device + simulator) and macOS, then create StarknetCrypto.xcframework.
# Requires: rustup, Xcode. Run from repo root.

set -e
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_DIR="$REPO_ROOT/Rust"
OUT_DIR="$REPO_ROOT/XCFrameworks"
XCFRAMEWORK_NAME="StarknetCrypto"
LIB_NAME="starknet_crypto_ffi"

# Targets (see https://doc.rust-lang.org/rustc/platform-support/apple-ios.html)
IOS_ARM64="aarch64-apple-ios"
IOS_SIM_ARM64="aarch64-apple-ios-sim"   # iOS Simulator on Apple Silicon
IOS_SIM_X64="x86_64-apple-ios"           # iOS Simulator on Intel
MACOS_ARM64="aarch64-apple-darwin"
MACOS_X64="x86_64-apple-darwin"

echo "Adding Rust targets if needed..."
rustup target add "$IOS_ARM64" "$IOS_SIM_ARM64" "$IOS_SIM_X64" "$MACOS_ARM64" "$MACOS_X64" 2>/dev/null || true

cd "$RUST_DIR"

echo "Building release staticlib for each target..."
cargo build --release --target "$IOS_ARM64"
cargo build --release --target "$IOS_SIM_ARM64"
cargo build --release --target "$IOS_SIM_X64"
cargo build --release --target "$MACOS_ARM64"
cargo build --release --target "$MACOS_X64"

mkdir -p "$OUT_DIR"
rm -rf "$OUT_DIR/$XCFRAMEWORK_NAME.xcframework"

# Headers dir for xcodebuild (must contain .h; modulemap goes in Modules/ for xcframework)
HEADERS_DIR="$OUT_DIR/Headers"
mkdir -p "$HEADERS_DIR"
cp "$RUST_DIR/StarknetCryptoFFI.h" "$HEADERS_DIR/"

# Simulator and macOS universal libs
IOS_SIM_A="$OUT_DIR/lib_ios_sim.a"
MACOS_A="$OUT_DIR/lib_macos.a"
lipo -create \
  "$RUST_DIR/target/$IOS_SIM_ARM64/release/lib$LIB_NAME.a" \
  "$RUST_DIR/target/$IOS_SIM_X64/release/lib$LIB_NAME.a" \
  -output "$IOS_SIM_A"
lipo -create \
  "$RUST_DIR/target/$MACOS_ARM64/release/lib$LIB_NAME.a" \
  "$RUST_DIR/target/$MACOS_X64/release/lib$LIB_NAME.a" \
  -output "$MACOS_A"

# Create xcframework using xcodebuild
xcodebuild -create-xcframework \
  -library "$RUST_DIR/target/$IOS_ARM64/release/lib$LIB_NAME.a" \
  -headers "$HEADERS_DIR" \
  -library "$IOS_SIM_A" \
  -headers "$HEADERS_DIR" \
  -library "$MACOS_A" \
  -headers "$HEADERS_DIR" \
  -output "$OUT_DIR/$XCFRAMEWORK_NAME.xcframework"

# Add module.modulemap to each slice so Swift can import the C module
XCFW="$OUT_DIR/$XCFRAMEWORK_NAME.xcframework"
for name in ios-arm64 ios-arm64_x86_64-simulator macos-arm64_x86_64; do
  if [ -d "$XCFW/$name/Headers" ]; then
    cp "$RUST_DIR/module.modulemap" "$XCFW/$name/Headers/"
  fi
done

rm -f "$IOS_SIM_A" "$MACOS_A"
rm -rf "$HEADERS_DIR"

echo "Done: $OUT_DIR/$XCFRAMEWORK_NAME.xcframework"
