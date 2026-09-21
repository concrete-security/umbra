import Foundation
import LocalVMContract

#if os(macOS) && arch(arm64)
import Darwin
import Virtualization

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data(("umbra-local-vm: " + message + "\n").utf8))
    exit(1)
}

func unixAddress(_ path: String) throws -> sockaddr_un {
    var address = sockaddr_un()
    let bytes = Array(path.utf8) + [0]
    guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else {
        throw ContractError.invalidConfiguration
    }
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { target in
        target.copyBytes(from: bytes)
    }
    return address
}

func unixSocket(_ path: String, listening: Bool) throws -> Int32 {
    let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ContractError.invalidConfiguration }
    _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
    do {
        var address = try unixAddress(path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                listening
                    ? Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                    : Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { throw ContractError.invalidConfiguration }
        if listening {
            guard chmod(path, 0o600) == 0, Darwin.listen(fd, 16) == 0 else {
                throw ContractError.invalidConfiguration
            }
        }
        return fd
    } catch {
        Darwin.close(fd)
        throw error
    }
}

func waitIO(_ fd: Int32, _ events: Int16) -> Bool {
    var item = pollfd(fd: fd, events: events, revents: 0)
    while true {
        let result = Darwin.poll(&item, 1, 1000)
        if result > 0 { return true }
        if result < 0 && errno != EINTR { return false }
    }
}

func pump(_ source: Int32, _ destination: Int32) {
    var bytes = [UInt8](repeating: 0, count: 65536)
    while true {
        let count = Darwin.read(source, &bytes, bytes.count)
        if count == 0 { break }
        if count < 0 {
            if errno == EINTR { continue }
            if errno == EAGAIN && waitIO(source, Int16(POLLIN)) { continue }
            break
        }
        var position = 0
        while position < count {
            let sent = bytes.withUnsafeBytes {
                Darwin.write(destination, $0.baseAddress!.advanced(by: position), count - position)
            }
            if sent > 0 { position += sent; continue }
            if sent < 0 && errno == EINTR { continue }
            if sent < 0 && errno == EAGAIN && waitIO(destination, Int16(POLLOUT)) { continue }
            _ = Darwin.shutdown(source, SHUT_RDWR)
            _ = Darwin.shutdown(destination, SHUT_RDWR)
            return
        }
    }
    _ = Darwin.shutdown(destination, SHUT_WR)
}

final class Relays {
    private let slots = DispatchSemaphore(value: 64)

    func start(_ local: Int32, connection: VZVirtioSocketConnection) {
        guard slots.wait(timeout: .now()) == .success else {
            Darwin.close(local)
            connection.close()
            return
        }
        let remote = dup(connection.fileDescriptor)
        guard remote >= 0 else {
            Darwin.close(local)
            connection.close()
            slots.signal()
            return
        }
        _ = fcntl(remote, F_SETFD, FD_CLOEXEC)
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) { pump(local, remote) }
        DispatchQueue.global().async(group: group) { pump(remote, local) }
        group.notify(queue: .main) {
            Darwin.close(local)
            Darwin.close(remote)
            connection.close()
            self.slots.signal()
        }
    }
}

final class Egress: NSObject, VZVirtioSocketListenerDelegate {
    let socketPath: String
    let relays: Relays
    init(_ socketPath: String, _ relays: Relays) {
        self.socketPath = socketPath
        self.relays = relays
    }

    func listener(_ listener: VZVirtioSocketListener,
                  shouldAcceptNewConnection connection: VZVirtioSocketConnection,
                  from socketDevice: VZVirtioSocketDevice) -> Bool {
        // The destination is fixed by the host, never supplied by the guest.
        guard let local = try? unixSocket(socketPath, listening: false) else { return false }
        relays.start(local, connection: connection)
        return true
    }
}

final class VMEvents: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { exit(0) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fail("guest stopped unexpectedly")
    }
}

func serve(_ path: String, port: UInt32, device: VZVirtioSocketDevice,
           relays: Relays) throws {
    let listener = try unixSocket(path, listening: true)
    DispatchQueue.global().async {
        while true {
            let client = Darwin.accept(listener, nil, nil)
            if client < 0 {
                if errno == EINTR { continue }
                break
            }
            _ = fcntl(client, F_SETFD, FD_CLOEXEC)
            DispatchQueue.main.async {
                device.connect(toPort: port) { result in
                    switch result {
                    case .success(let connection): relays.start(client, connection: connection)
                    case .failure: Darwin.close(client)
                    }
                }
            }
        }
        Darwin.close(listener)
    }
}

signal(SIGPIPE, SIG_IGN)
umask(0o077)
guard CommandLine.arguments.count == 2 else { fail("expected one VM configuration file") }
let configuration: VMConfiguration
do {
    configuration = try VMConfiguration.decode(Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1])))
} catch { fail("invalid VM configuration") }

let config = VZVirtualMachineConfiguration()
let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: configuration.kernel))
boot.initialRamdiskURL = URL(fileURLWithPath: configuration.initrd)
boot.commandLine = VMConfiguration.kernelCommandLine
config.bootLoader = boot
config.cpuCount = configuration.cpus
config.memorySize = configuration.memoryMiB * 1024 * 1024
config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
config.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
// The security boundary: no NIC, no NAT, no bridge, no shared host directory.
config.networkDevices = []
config.directorySharingDevices = []
let console = VZVirtioConsoleDeviceSerialPortConfiguration()
console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: FileHandle.standardError)
config.serialPorts = [console]
do {
    let disk = try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: configuration.disk), readOnly: false)
    config.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: disk)]
    try config.validate()
} catch { fail("VM configuration or guest image is unsupported") }

let vm = VZVirtualMachine(configuration: config)
let events = VMEvents()
vm.delegate = events
let relays = Relays()
let egress = Egress(configuration.socketDirectory + "/proxy.sock", relays)
let egressListener = VZVirtioSocketListener()
egressListener.delegate = egress
guard let sockets = vm.socketDevices.first as? VZVirtioSocketDevice else { fail("vsock unavailable") }
sockets.setSocketListener(egressListener, forPort: VMConfiguration.egressPort)
do {
    try serve(configuration.socketDirectory + "/ssh.sock", port: VMConfiguration.sshPort, device: sockets, relays: relays)
    try serve(configuration.socketDirectory + "/boot.sock", port: VMConfiguration.bootstrapPort, device: sockets, relays: relays)
} catch { fail("cannot create private VM control sockets") }

signal(SIGTERM, SIG_IGN)
signal(SIGINT, SIG_IGN)
let termination = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
let interruption = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
func stop() {
    do { try vm.requestStop() } catch { exit(1) }
    DispatchQueue.main.asyncAfter(deadline: .now() + 15) { exit(1) }
}
termination.setEventHandler { stop() }
interruption.setEventHandler { stop() }
termination.resume()
interruption.resume()
let parent = getppid()
let watchdog = DispatchSource.makeTimerSource(queue: .main)
watchdog.schedule(deadline: .now() + 2, repeating: 2)
watchdog.setEventHandler { if getppid() != parent { stop() } }
watchdog.resume()
vm.start { result in
    switch result {
    case .success: break
    case .failure: fail("VM could not start; check virtualization entitlement and guest bundle")
    }
}
dispatchMain()
#else
FileHandle.standardError.write(Data("umbra-local-vm requires an Apple-silicon Mac\n".utf8))
exit(1)
#endif
