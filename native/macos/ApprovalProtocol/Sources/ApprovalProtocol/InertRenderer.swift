import Foundation

public struct ApprovalDisplaySnapshot: Equatable, Sendable {
    public static let maximumBytes = 524_288

    // Data is a copy-on-write value. This retained value is the single source
    // for both the visible representation and the digest used by its caller.
    public let bytes: Data

    public init(bytes: Data) throws {
        guard !bytes.isEmpty, bytes.count <= Self.maximumBytes else {
            throw ApprovalProtocolError.inputTooLarge(limit: Self.maximumBytes)
        }
        self.bytes = bytes
    }

    public func inertEscapedBytes() -> String {
        var output = ""
        output.reserveCapacity(bytes.count)
        let hex = Array("0123456789ABCDEF")
        for byte in bytes {
            if byte >= 0x20, byte <= 0x7E, byte != 0x5C {
                output.unicodeScalars.append(UnicodeScalar(byte))
            } else if byte == 0x5C {
                output.append("\\\\")
            } else {
                output.append("\\x")
                output.append(hex[Int(byte >> 4)])
                output.append(hex[Int(byte & 0x0F)])
            }
        }
        return output
    }

    public static func decodeInertEscapedBytes(_ value: String) throws -> Data {
        guard value.utf8.count <= maximumBytes * 4 else {
            throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes * 4)
        }
        let bytes = Array(value.utf8)
        var output = Data()
        output.reserveCapacity(bytes.count)
        var offset = 0
        while offset < bytes.count {
            let byte = bytes[offset]
            guard byte >= 0x20, byte <= 0x7E else {
                throw ApprovalProtocolError.invalidEscapedBytes
            }
            if byte != 0x5C {
                guard output.count < maximumBytes else {
                    throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes)
                }
                output.append(byte)
                offset += 1
                continue
            }
            guard offset + 1 < bytes.count else {
                throw ApprovalProtocolError.invalidEscapedBytes
            }
            if bytes[offset + 1] == 0x5C {
                guard output.count < maximumBytes else {
                    throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes)
                }
                output.append(0x5C)
                offset += 2
                continue
            }
            guard offset + 3 < bytes.count, bytes[offset + 1] == 0x78,
                  let high = hexValue(bytes[offset + 2]), let low = hexValue(bytes[offset + 3])
            else {
                throw ApprovalProtocolError.invalidEscapedBytes
            }
            guard output.count < maximumBytes else {
                throw ApprovalProtocolError.inputTooLarge(limit: maximumBytes)
            }
            output.append((high << 4) | low)
            offset += 4
        }
        guard !output.isEmpty else {
            throw ApprovalProtocolError.invalidEscapedBytes
        }
        let canonical = try ApprovalDisplaySnapshot(bytes: output).inertEscapedBytes()
        guard canonical == value else {
            throw ApprovalProtocolError.invalidEscapedBytes
        }
        return output
    }
}

private func hexValue(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 0x30...0x39: byte - 0x30
    case 0x41...0x46: byte - 0x41 + 10
    default: nil
    }
}
