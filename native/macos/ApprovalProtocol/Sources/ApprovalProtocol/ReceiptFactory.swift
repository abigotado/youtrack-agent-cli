import Foundation

public struct ApprovalSigningKeyIdentity: Equatable, Sendable {
    public let generation: String
    public let spkiDER: Data
    public let fingerprintSHA256: String

    public init(generation: String, spkiDER input: Data) throws {
        let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: input)
        let copied = input.withUnsafeBytes { Data($0) }
        guard generation.utf8.count <= 64, !generation.isEmpty else { throw ApprovalProtocolError.invalidField("key_generation") }
        // Receipt parsing is the shared authority for the complete generation grammar.
        let bytes = Array(generation.utf8)
        func alnum(_ byte: UInt8) -> Bool {
            (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
        }
        guard alnum(bytes[0]), bytes.dropFirst().allSatisfy({ alnum($0) || [0x2E, 0x5F, 0x2D].contains($0) }) else {
            throw ApprovalProtocolError.invalidField("key_generation")
        }
        self.generation = generation
        spkiDER = copied
        fingerprintSHA256 = try P256PublicKeyCodec.fingerprintSHA256(x963: x963)
    }
}

public protocol ApprovalSigner: AnyObject {
    var keyIdentity: ApprovalSigningKeyIdentity { get }
    func sign(message: Data) throws -> Data
}

public protocol CryptographicRandomSource {
    func randomBytes(count: Int) throws -> Data
}

public protocol ApprovalClock {
    func now() -> Date
}

public enum ApprovalReceiptFactory {
    public static func makeReceipt(
        for snapshot: ValidatedPlanSnapshot,
        signer: any ApprovalSigner,
        random: any CryptographicRandomSource,
        clock: any ApprovalClock
    ) throws -> ApprovalReceipt {
        let identity = signer.keyIdentity
        // Revalidate a defensive copy before the key is asked to sign.
        _ = try ApprovalSigningKeyIdentity(generation: identity.generation, spkiDER: identity.spkiDER)
        let receiptID = try identifier(prefix: "YTAR-", random: random)
        let nonce = try identifier(prefix: "YTAN-", random: random)
        let issued = floor(clock.now().timeIntervalSince1970)
        guard issued.isFinite, issued >= -62_135_596_800, issued < 253_402_300_800 else {
            throw ApprovalProtocolError.invalidField("issued_at")
        }
        let issuedAt = try utcString(seconds: Int64(issued))
        let expiresAt = try utcString(seconds: Int64(issued) + 120)
        let binding = snapshot.bindings
        let unsigned = try UnsignedApprovalReceipt(
            receiptID: receiptID, nonce: nonce, planID: binding.planID,
            planSHA256: binding.planSHA256, profileIdentitySHA256: binding.profileIdentitySHA256,
            accountID: binding.accountID, projectID: binding.projectID, projectKey: binding.projectKey,
            schemaSHA256: binding.schemaSHA256, requestSHA256: binding.requestSHA256,
            expectedSHA256: binding.expectedSHA256, issuedAt: issuedAt, expiresAt: expiresAt,
            keyGeneration: identity.generation, keyFingerprintSHA256: identity.fingerprintSHA256
        )
        let message = unsigned.encodedSigningBytes()
        let signerOutput = try signer.sign(message: message) // Exactly one signing call.
        let signature = try P256Signature.normalizeLowS(der: signerOutput)
        let x963 = try P256PublicKeyCodec.x963(fromSPKIDER: identity.spkiDER)
        guard try P256PublicKeyCodec.verify(message: message, derSignature: signature.der, x963: x963) else {
            throw ApprovalProtocolError.invalidSignature
        }
        let receipt = try ApprovalReceipt(unsigned: unsigned, signatureDER: signature.der)
        return try ApprovalReceipt(receiptBytes: receipt.encodedReceiptBytes())
    }

    private static func identifier(prefix: String, random: any CryptographicRandomSource) throws -> String {
        let bytes = try random.randomBytes(count: 16)
        guard bytes.count == 16 else { throw ApprovalProtocolError.invalidField("random") }
        let raw = Array(bytes)
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
        var encoded = ""
        for group in 0..<26 {
            var value = 0
            for bit in 0..<5 {
                let bitIndex = group * 5 + bit
                value <<= 1
                if bitIndex < 128 {
                    let byte = raw[bitIndex / 8]
                    value |= Int((byte >> UInt8(7 - bitIndex % 8)) & 1)
                }
            }
            encoded.append(Character(UnicodeScalar(alphabet[value])))
        }
        return prefix + encoded
    }

    private static func utcString(seconds: Int64) throws -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        guard let year = c.year, (1...9999).contains(year), let month = c.month, let day = c.day,
              let hour = c.hour, let minute = c.minute, let second = c.second
        else { throw ApprovalProtocolError.invalidField("issued_at") }
        return String(format: "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second)
    }
}
