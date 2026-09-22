// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "UmbraLocalVM",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "umbra-local-vm", targets: ["UmbraLocalVM"])],
    targets: [
        .target(name: "LocalVMContract"),
        .executableTarget(name: "UmbraLocalVM", dependencies: ["LocalVMContract"]),
        .testTarget(name: "LocalVMContractTests", dependencies: ["LocalVMContract"]),
    ],
    swiftLanguageModes: [.v5]
)
