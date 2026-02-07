// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "StarknetCryptoSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15),
    ],
    products: [
        .library(name: "StarknetCrypto", targets: ["StarknetCrypto"]),
    ],
    targets: [
        .binaryTarget(
            name: "StarknetCryptoFFI",
            path: "XCFrameworks/StarknetCrypto.xcframework"
        ),
        .target(
            name: "StarknetCrypto",
            dependencies: ["StarknetCryptoFFI"],
            path: "Sources/StarknetCrypto"
        ),
        .testTarget(
            name: "StarknetCryptoTests",
            dependencies: ["StarknetCrypto"],
            path: "Tests/StarknetCryptoTests"
        ),
    ]
)
