import Foundation
import Testing
@testable import LocalVMContract

struct ConfigurationTests {
    let valid: [String: Any] = [
        "kernel": "/bundle/Image", "initrd": "/bundle/initrd", "disk": "/state/disk.raw",
        "socketDirectory": "/state", "cpus": 4, "memoryMiB": 4096,
    ]

    /// The minimal host contract has no externally configurable network fields.
    @Test func test_valid_configuration_success() throws {
        let decoded = try VMConfiguration.decode(JSONSerialization.data(withJSONObject: valid))
        #expect(decoded.cpus == 4)
    }

    /// Foundation must not reject Python's canonical /private macOS paths.
    @Test func test_existing_canonical_directory_success() throws {
        var value = valid
        value["socketDirectory"] = "/private/tmp"
        let decoded = try VMConfiguration.decode(JSONSerialization.data(withJSONObject: value))
        #expect(decoded.socketDirectory == value["socketDirectory"] as? String)
    }

    /// Additional device or command fields cannot expand the host boundary.
    @Test func test_unknown_capability_failure() throws {
        for key in ["networkDevices", "nat", "mounts", "command", "kernelCommandLine", "proxyToken"] {
            var value = valid
            value[key] = "untrusted"
            #expect(throws: (any Error).self) {
                try VMConfiguration.decode(JSONSerialization.data(withJSONObject: value))
            }
        }
    }

    /// Malformed paths and resource requests fail before Virtualization is used.
    @Test func test_invalid_configuration_failure() throws {
        let cases: [(String, Any)] = [
            ("kernel", "relative"), ("disk", "/state/../disk"), ("initrd", "/bundle/Image"),
            ("cpus", 0), ("memoryMiB", 65537), ("socketDirectory", "/" + String(repeating: "x", count: 100)),
            ("socketDirectory", "/" + String(repeating: "x", count: 91)),
            ("kernel", "/bundle/\nImage"),
        ]
        for (key, replacement) in cases {
            var value = valid
            value[key] = replacement
            #expect(throws: (any Error).self) {
                try VMConfiguration.decode(JSONSerialization.data(withJSONObject: value))
            }
        }
    }
}
