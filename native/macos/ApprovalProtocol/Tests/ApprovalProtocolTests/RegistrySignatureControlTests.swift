import CryptoKit
import Foundation
import Testing
@testable import ApprovalProtocol

private func signatureControlHex(_ text: String) throws -> Data {
    let bytes = Array(text.utf8)
    try #require(bytes.count.isMultiple(of: 2))
    return try Data(stride(from: 0, to: bytes.count, by: 2).map {
        try #require(UInt8(String(decoding: bytes[$0..<$0 + 2], as: UTF8.self), radix: 16))
    })
}

// Frozen public fixture from fixed test scalar 9, independently verified using
// Go's standard ECDSA implementation. No test requires a native defect to persist.
private struct RegistrySignatureControlFixture {
    let message: Data
    let low: Data
    let high: Data
    let lowRaw: Data
    let highRaw: Data
    let key: Data
    let wrongKey: Data

    init() throws {
        message = try signatureControlHex(
            "5954412d52454749535452592d5245434f52442d4f4c442d5631007b22736368656d615f76657273696f6e223a312c227265636f72645f7479706522" +
            "3a22617070726f76616c5f72656769737472795f7472616e736974696f6e222c227472616e736974696f6e5f6b696e64223a22726f74617465222c22" +
            "72656769737472795f7265766973696f6e223a31302c2270726576696f75735f7265636f72645f736861323536223a22333537646662613230306634" +
            "35663432393134616433643731653033353765636364613161633363333739653234396136396233343238303461643532636632222c227265717565" +
            "73745f736861323536223a22396664323162336131623666393264346139303131323162326661333464633866373665636630326434383738366430" +
            "65353264373039353031363864303830222c2270726f706f73616c5f736861323536223a226538376137333134303436396238666661616332626238" +
            "3633373837613266643635633437646131373261613330646165306664633561393364646131393835222c22616363657074616e63655f7368613235" +
            "36223a223931663033366530373162336565316435666333663934646663383036336362616231396232353533356534376534376435336434643633" +
            "6535613633303534222c226368616c6c656e67655f736861323536223a22303437376664386531356263363861386431636532323738316664623930" +
            "64656464643763646636353765353237663935666339386262653639313833333765222c2261727469666163745f64657363726970746f725f736861" +
            "323536223a22616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161" +
            "61616161616161616161222c227265636f766572795f65766964656e63655f736861323536223a6e756c6c2c227265717565737465645f6174223a22" +
            "323032362d30392d30315431323a30303a30305a222c2261636365707465645f6174223a22323032362d30392d30315431323a30303a30325a222c22" +
            "636f6d6d69747465645f6174223a22323032362d30392d30315431323a30303a30335a222c227461726765745f67656e65726174696f6e223a225954" +
            "41472d3030303030303030303030303030303030303039222c227461726765745f6b65795f6964223a22303030303030303030303030303030303030" +
            "3030303030303030303030303039222c227461726765745f6b65795f746167223a22696f2e6769746875622e616269676f7461646f2e796f75747261" +
            "636b2d6167656e742e617070726f76616c2e7369676e696e672e76312f30303030303030303030303030303030303030303030303030303030303030" +
            "39222c227461726765745f73706b69223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a30444151634451674145366d6a587476" +
            "37664333474869546a56485848346370344b793477736266697a3135364b533543556e7541714a30544a63736e383534634253705a4b6a7144495458" +
            "465036715465676a5f6f57694a4b546442492d67222c227461726765745f66696e6765727072696e745f736861323536223a22653336313566666633" +
            "37343734633536316330363864316635366635656333373531636437656232656137303436633031366131343263393332383635343936222c227461" +
            "726765745f70726576696f75735f737461747573223a22616374697665222c227461726765745f6e65775f737461747573223a2272657461696e6564" +
            "222c226e65775f67656e65726174696f6e223a22595441472d3030303030303030303030303030303030303130222c226e65775f6b65795f6964223a" +
            "223030303030303030303030303030303030303030303030303030303030303061222c226e65775f6b65795f746167223a22696f2e6769746875622e" +
            "616269676f7461646f2e796f75747261636b2d6167656e742e617070726f76616c2e7369676e696e672e76312f303030303030303030303030303030" +
            "3030303030303030303030303030303061222c226e65775f73706b69223a224d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441" +
            "516344516741457a765a7461796f366d54355a456854523669495f7455584b6245636353444275544459476c415446636a2d48686d4b694b6171756b" +
            "473453504e32644f307751575133744b6635314875374b4e4c7571524b38486377222c226e65775f66696e6765727072696e745f736861323536223a" +
            "226630663661303030336664396539346666623136653232303663666466323732656632653838363064373366333237303462356633363562343535" +
            "3035313338222c226e65775f737461747573223a22616374697665222c227265766f6b65735f616c6c5f7072696f72223a66616c73657d")
        low = try signatureControlHex("3044022051569648e91fee2b4e947ebbef3756773a51bf1c321d31d6419d11f51d48264a02206a1bfeb307a994ea558c3065bf46e4b0693bcc6bfdedfb531615092b0c0908f2")
        high = try signatureControlHex("3045022051569648e91fee2b4e947ebbef3756773a51bf1c321d31d6419d11f51d48264a02210095e4014bf8566b16aa73cf9a40b91b4f53ab2e41a929a331dda4c197f05a1c5f")
        lowRaw = try signatureControlHex("51569648e91fee2b4e947ebbef3756773a51bf1c321d31d6419d11f51d48264a6a1bfeb307a994ea558c3065bf46e4b0693bcc6bfdedfb531615092b0c0908f2")
        highRaw = try signatureControlHex("51569648e91fee2b4e947ebbef3756773a51bf1c321d31d6419d11f51d48264a95e4014bf8566b16aa73cf9a40b91b4f53ab2e41a929a331dda4c197f05a1c5f")
        key = try signatureControlHex("04ea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee02a2744c972c9fce787014a964a8ea0c84d714feaa4de823fe85a224a4dd048fa")
        wrongKey = try signatureControlHex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        try #require(message.count == 1_795)
        let digest = SHA256.hash(data: message).map { String(format: "%02x", $0) }.joined()
        try #require(digest == "0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba")
        let spki = try signatureControlHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004ea68d7b6fedf0b71878938d51d71f8729e0acb8c2c6df8b3d79e8a4b90949ee02a2744c972c9fce787014a964a8ea0c84d714feaa4de823fe85a224a4dd048fa")
        try #require(P256PublicKeyCodec.x963(fromSPKIDER: spki) == key)
        var scalar = Data(repeating: 0, count: 32)
        scalar[31] = 9
        let knownKey = try P256.Signing.PrivateKey(rawRepresentation: scalar)
        try #require(knownKey.publicKey.x963Representation == key)
        try #require(key != wrongKey)
    }
}

@Test func registrySignatureControlAcceptsFrozenEquivalentSignatures() throws {
    let fixture = try RegistrySignatureControlFixture()
    let nativeKey = try P256.Signing.PublicKey(x963Representation: fixture.key)
    for (name, der) in [("low-S", fixture.low), ("high-S", fixture.high)] {
        let nativeSignature = try P256.Signing.ECDSASignature(derRepresentation: der)
        let originalAccepted = nativeKey.isValidSignature(nativeSignature, for: fixture.message)
        let outcome = try registrySignatureControlOutcome(message: fixture.message, derSignature: der, x963: fixture.key)
        let expected: RegistrySignatureControlOutcome = originalAccepted ? .original : .equivalent
        #expect(outcome == expected, "\(name)")
        print("registry_signature_control form=\(name) outcome=\(outcome)")
        #expect(try registrySignatureControl(message: fixture.message, derSignature: der, x963: fixture.key), "\(name)")
    }
}

@Test func registrySignatureControlFrozenDERMatchesRawScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    try #require(fixture.low.count == 70)
    try #require(fixture.high.count == 71)
    #expect(fixture.low.prefix(4) == Data([0x30, 0x44, 0x02, 0x20]))
    #expect(fixture.low[36..<38] == Data([0x02, 0x20]))
    #expect(fixture.high.prefix(4) == Data([0x30, 0x45, 0x02, 0x20]))
    #expect(fixture.high[36..<39] == Data([0x02, 0x21, 0]))
    // Fixed DER offsets expose the two independently verified scalar magnitudes.
    #expect(Data(fixture.low[4..<36]) + Data(fixture.low[38..<70]) == fixture.lowRaw)
    #expect(Data(fixture.high[4..<36]) + Data(fixture.high[39..<71]) == fixture.highRaw)
    #expect(try P256.Signing.ECDSASignature(derRepresentation: fixture.low).rawRepresentation == fixture.lowRaw)
    #expect(try P256.Signing.ECDSASignature(derRepresentation: fixture.high).rawRepresentation == fixture.highRaw)
    #expect(try P256Signature(der: fixture.low).der == fixture.low)
}

@Test func registrySignatureControlTwinPreservesFrozenScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    #expect(try registrySignatureControlTwin(raw: fixture.lowRaw) == fixture.highRaw)
    #expect(try registrySignatureControlTwin(raw: fixture.highRaw) == fixture.lowRaw)
    for raw in [fixture.lowRaw, fixture.highRaw] {
        let twin = try registrySignatureControlTwin(raw: raw)
        #expect(twin.prefix(32) == raw.prefix(32))
        #expect(try registrySignatureControlTwin(raw: twin) == raw)
    }
}

@Test func registrySignatureControlTwinHandlesScalarBoundaries() throws {
    // Expected N-s values were calculated independently with Go math/big.
    let r = try signatureControlHex("0000000000000000000000000000000000000000000000000000000000000001")
    let cases = [
        ("one", "0000000000000000000000000000000000000000000000000000000000000001", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"),
        ("order minus one", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", "0000000000000000000000000000000000000000000000000000000000000001"),
        ("byte boundary", "0000000000000000000000000000000000000000000000000000000000000100", "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632451"),
        ("borrow across zeros", "0000000000000001000000000000000000000000000000000000000000000000", "fffffffeffffffffffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
    ]
    for (name, scalar, expectedScalar) in cases {
        let raw = r + (try signatureControlHex(scalar))
        let expected = r + (try signatureControlHex(expectedScalar))
        let twin = try registrySignatureControlTwin(raw: raw)
        #expect(twin == expected, "\(name)")
        #expect(try registrySignatureControlTwin(raw: twin) == raw, "\(name)")
    }
}

@Test func registrySignatureControlTwinRejectsInvalidRawScalars() throws {
    let fixture = try RegistrySignatureControlFixture()
    let zero = Data(repeating: 0, count: 32)
    let one = try signatureControlHex("0000000000000000000000000000000000000000000000000000000000000001")
    let order = try signatureControlHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    let cases: [(String, Data)] = [
        ("short", Data(fixture.lowRaw.dropLast())),
        ("long", fixture.lowRaw + Data([0])),
        ("zero r", zero + one),
        ("zero s", one + zero),
        ("out-of-range r", order + one),
        ("out-of-range s", one + order),
    ]
    for (name, raw) in cases {
        #expect(throws: RegistrySignatureControlError.invalidSignature, "\(name)") {
            try registrySignatureControlTwin(raw: raw)
        }
    }
}

@Test func registrySignatureControlRejectsChangedInputs() throws {
    let fixture = try RegistrySignatureControlFixture()
    for (form, der) in [("low-S", fixture.low), ("high-S", fixture.high)] {
        var wrongR = der
        wrongR[35] ^= 1
        var wrongS = der
        wrongS[wrongS.count - 1] ^= 1
        let cases: [(String, Data, Data, Data)] = [
            ("message", fixture.message + Data([0]), der, fixture.key),
            ("key", fixture.message, der, fixture.wrongKey),
            ("r", fixture.message, wrongR, fixture.key),
            ("s", fixture.message, wrongS, fixture.key),
        ]
        for (name, message, signature, key) in cases {
            #expect(try registrySignatureControlOutcome(message: message, derSignature: signature, x963: key) == .rejected, "\(form) changed \(name)")
            #expect(try !registrySignatureControl(message: message, derSignature: signature, x963: key), "\(form) changed \(name)")
        }
    }
}

@Test func registrySignatureControlRejectsMalformedSignatures() throws {
    let fixture = try RegistrySignatureControlFixture()
    let order = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("truncated", try signatureControlHex("30060201010201")),
        ("trailing data", fixture.low + Data([0])),
        ("zero r", try signatureControlHex("3006020100020101")),
        ("zero s", try signatureControlHex("3006020101020100")),
        ("out-of-range r", try signatureControlHex("3026022100" + order + "020101")),
        ("out-of-range s", try signatureControlHex("3026020101022100" + order)),
        ("negative integer", try signatureControlHex("3006020180020101")),
        ("nonminimal integer", try signatureControlHex("300702020001020101")),
        ("nonminimal sequence length", try signatureControlHex("308106020101020101")),
    ]
    for (name, der) in cases {
        #expect(throws: RegistrySignatureControlError.invalidSignature, "\(name)") {
            try registrySignatureControl(message: fixture.message, derSignature: der, x963: fixture.key)
        }
    }
}

@Test func registrySignatureControlRejectsInvalidPublicKeys() throws {
    let fixture = try RegistrySignatureControlFixture()
    var invalidPoint = Data(repeating: 0, count: 65)
    invalidPoint[0] = 0x04
    var wrongPrefix = fixture.key
    wrongPrefix[0] = 0x02
    let cases: [(String, Data)] = [
        ("empty", Data()),
        ("short", Data(fixture.key.dropLast())),
        ("long", fixture.key + Data([0])),
        ("wrong prefix", wrongPrefix),
        ("off-curve point", invalidPoint),
    ]
    for (name, key) in cases {
        #expect(throws: RegistrySignatureControlError.invalidPublicKey, "\(name)") {
            try registrySignatureControl(message: fixture.message, derSignature: fixture.low, x963: key)
        }
    }
}

@Test func registrySignatureControlPreservesProductionLowSIngress() throws {
    let fixture = try RegistrySignatureControlFixture()
    _ = try P256Signature(der: fixture.low)
    #expect(try P256PublicKeyCodec.verify(message: fixture.message, derSignature: fixture.low, x963: fixture.key))
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try P256Signature(der: fixture.high)
    }
    #expect(throws: ApprovalProtocolError.invalidSignature) {
        _ = try P256PublicKeyCodec.verify(message: fixture.message, derSignature: fixture.high, x963: fixture.key)
    }
}
