import Foundation

public enum ContractError: Error {
    case invalidConfiguration
}

/// Deliberately no network, mount, host-command, kernel-argument or token fields.
public struct VMConfiguration: Codable {
    public let kernel: String
    public let initrd: String
    public let disk: String
    public let socketDirectory: String
    public let cpus: Int
    public let memoryMiB: UInt64

    public static let egressPort: UInt32 = 4050
    public static let bootstrapPort: UInt32 = 4051
    public static let sshPort: UInt32 = 22
    public static let kernelCommandLine = "console=hvc0 root=/dev/vda rw rootwait"

    public static func decode(_ data: Data) throws -> VMConfiguration {
        let expected: Set<String> = ["kernel", "initrd", "disk", "socketDirectory", "cpus", "memoryMiB"]
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == expected else { throw ContractError.invalidConfiguration }
        let config = try JSONDecoder().decode(Self.self, from: data)
        guard (2...32).contains(config.cpus), (1024...65536).contains(config.memoryMiB) else {
            throw ContractError.invalidConfiguration
        }
        for path in [config.kernel, config.initrd, config.disk, config.socketDirectory] {
            guard path.hasPrefix("/"), !path.utf8.contains(where: { $0 < 32 || $0 == 127 }),
                  (path == "/" || path.split(separator: "/", omittingEmptySubsequences: false)
                .dropFirst().allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }) else {
                throw ContractError.invalidConfiguration
            }
        }
        guard Set([config.kernel, config.initrd, config.disk]).count == 3,
              config.socketDirectory.utf8.count + "/control.sock".utf8.count < 104 else {
            throw ContractError.invalidConfiguration
        }
        return config
    }
}
