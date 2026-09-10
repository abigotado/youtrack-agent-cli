import CryptoKit
import Foundation
import Testing

// Offline fixture oracle only; no coordinator, native authority, or runtime API.
private enum IntentFailure: String, Error {
    case canonical = "canonical_encoding"
    case bounds = "bounds_grammar"
    case temporal
    case digest = "digest_domain"
    case binding = "intent_binding"
}

private enum IntentFixtureError: Error { case malformedHex, unknownCore, invalidCore }

private struct IntentCorpus: Decodable {
    struct Source: Decodable { let path: String; let sha256: String }
    struct Positive: Decodable {
        let id: String; let core_id: String?; let raw_hex: String
        let signing_input_hex: String; let sha256: String
    }
    struct Negative: Decodable {
        let id: String; let base: String; let core_id: String?
        let raw_hex: String; let sha256: String; let reason_class: String
    }
    let schema_version: Int; let scope: String; let source: Source
    let positives: [Positive]; let negatives: [Negative]
}

private func intentFixtureData(_ path: String) throws -> Data {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<6 { root.deleteLastPathComponent() }
    return try Data(contentsOf: root.appendingPathComponent(path))
}

private func intentHex(_ bytes: Data) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

private func intentBytes(_ hex: String) throws -> Data {
    guard hex.utf8.count % 2 == 0, hex.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
        throw IntentFixtureError.malformedHex
    }
    let characters = Array(hex.utf8)
    return Data(stride(from: 0, to: characters.count, by: 2).map {
        UInt8(String(decoding: characters[$0..<$0 + 2], as: UTF8.self), radix: 16)!
    })
}

private func intentInput(_ bytes: Data) -> Data {
    Data("YTA-REGISTRY-INTENT-V1\0".utf8) + bytes
}

private func intentDigest(_ bytes: Data) -> String { intentHex(Data(SHA256.hash(data: intentInput(bytes)))) }

private func validatedIntentCore(_ id: String?, corpus: RegistryCorpus) throws -> RegistryObject? {
    guard let id else { return nil }
    guard let core = corpus.positives.first(where: { $0.id == id }),
          core.prefix.allSatisfy({ reference in corpus.positives.contains { $0.id == reference } }) else {
        throw IntentFixtureError.unknownCore
    }
    do {
        var ledger = try registryPrefix(core.prefix, corpus: corpus)
        try ledger.validate(core.transcript)
        return try RegistryObject(core.request, keys: registryRequestKeys, cap: 2048)
    } catch { throw IntentFixtureError.invalidCore }
}

private func validateIntent(_ bytes: Data, digest: String, coreID: String?, corpus: RegistryCorpus) throws -> RegistryObject {
    // Broken references and invalid signed transcripts are fixture defects,
    // never a successful negative intent verdict. Replay the full core first.
    let request = try validatedIntentCore(coreID, corpus: corpus)
    guard bytes.count <= 1024 else { throw IntentFailure.bounds }
    guard let raw = String(data: bytes, encoding: .utf8) else { throw IntentFailure.canonical }
    let intent: RegistryObject
    do {
        intent = try RegistryObject(raw, keys: ["schema_version", "intent_type", "transition_kind", "artifact_descriptor_sha256", "ceremony_nonce", "requested_at", "expires_at"], cap: 1024, checkGrammar: false)
        guard intent["schema_version"].range(of: "^(0|[1-9][0-9]*|-[1-9][0-9]*)$", options: .regularExpression) != nil,
              intent.fields.dropFirst().allSatisfy({ intent.string($0.0) != nil }) else { throw IntentFailure.canonical }
        try intent.grammar()
        guard intent.string("intent_type") == "registry_commit",
              ["enroll", "rotate", "revoke", "recover"].contains(intent.string("transition_kind") ?? "") else { throw IntentFailure.bounds }
        _ = try registryBase64(intent.string("ceremony_nonce") ?? "", count: 32)
    } catch RegistryReason.canonicalEncoding { throw IntentFailure.canonical }
    catch let error as RegistryReason {
        guard error == .boundsGrammar else { throw error }
        throw IntentFailure.bounds
    }
    let duration = try intent.time("expires_at").timeIntervalSince(intent.time("requested_at"))
    guard duration >= 1, duration <= 300 else { throw IntentFailure.temporal }
    guard digest == intentDigest(bytes) else { throw IntentFailure.digest }
    if let request {
        guard intent.string("transition_kind") == request.string("transition_kind"),
              intent.string("artifact_descriptor_sha256") == request.string("artifact_descriptor_sha256"),
              try registryBase64(intent.string("ceremony_nonce")!, count: 32) == registryBase64(request.string("challenge")!, count: 32),
              intent.string("expires_at") == request.string("expires_at") else { throw IntentFailure.binding }
    }
    return intent
}

@Test func registryIntentSharedCorpus() throws {
    let corpus = try JSONDecoder().decode(IntentCorpus.self, from: intentFixtureData("testdata/gate1a-registry-intent/corpus.json"))
    let core = try registryCorpus()
    #expect(corpus.schema_version == 1)
    #expect(corpus.scope == "registry-intent-binding")
    #expect(corpus.source.path == "testdata/gate1a-registry/corpus.json")
    #expect(corpus.source.sha256 == intentHex(Data(SHA256.hash(data: try intentFixtureData("testdata/gate1a-registry/corpus.json")))))
    let expected: [(String, String?, String)] = [
        ("intent-enroll1", "enroll1", "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67"),
        ("intent-rotate2", "rotate2", "e122718b57b090b792ad13ecbb347a0d3181d9e3c1217bd590d061af0cc56c87"),
        ("intent-revoke3", "revoke3", "713452b672826409337bbd53668ab09157a265cfe2db5ce2884d33adbb5b387f"),
        ("intent-recover-disabled4", "recover-disabled4", "8ccd7960f14afea3c3efbb4605f4e01c537f39facf4ac7403da19b8b03442612"),
        ("intent-recover-active3", "recover-active3", "de2c3928d468b22ed606840441758ccfadcae491a17493dc93f8adf8065f51f9"),
        ("ttl-1s", nil, "2abebaaa0750eb86ce1cfe7d360742623afca9a49e8b831f20476fbf56014e73"),
        ("ttl-300s", nil, "d4e4dc20ba7cc0295a3affd81dc28bc4fd38c836211eddcc4c2da529f1692b67"),
    ]
    try #require(corpus.positives.map(\.id) == expected.map(\.0))
    for (vector, pinned) in zip(corpus.positives, expected) {
        #expect(vector.core_id == pinned.1)
        let bytes = try intentBytes(vector.raw_hex)
        let intent = try validateIntent(bytes, digest: pinned.2, coreID: pinned.1, corpus: core)
        #expect(vector.sha256 == pinned.2)
        #expect(intentDigest(bytes) == pinned.2)
        #expect(vector.signing_input_hex == intentHex(intentInput(bytes)))
        #expect(try intent.time("expires_at").timeIntervalSince(intent.time("requested_at")) == (vector.id == "ttl-1s" ? 1 : 300))
        if let id = pinned.1 {
            let request = try #require(try validatedIntentCore(id, corpus: core))
            // This is a property of these full-window fixtures only. The binding
            // validator intentionally does not enforce requested_at equality.
            #expect(intent.string("requested_at") == request.string("requested_at"))
        }
    }
    let families: [(IntentFailure, String)] = [
        (.canonical, "canonical-empty canonical-malformed canonical-unknown canonical-duplicate canonical-missing canonical-reordered canonical-whitespace canonical-trailing-lf canonical-trailing-token canonical-escaped-key canonical-escaped-value canonical-invalid-utf8 canonical-schema-string canonical-schema-bool canonical-null canonical-array canonical-object canonical-schema-fraction canonical-schema-exponent canonical-schema-leading-zero canonical-schema-plus canonical-schema-negative-zero canonical-size-1024"),
        (.bounds, "bounds-size-1025 schema-version field-intent-type field-transition field-descriptor-uppercase field-descriptor-short field-descriptor-long field-descriptor-nonhex field-nonce-padding field-nonce-alphabet field-nonce-31-bytes field-nonce-33-bytes field-nonce-pad-bits field-date-offset field-date-fraction field-date-invalid"),
        (.temporal, "temporal-zero temporal-negative temporal-301s"),
        (.digest, "digest-wrong digest-no-nul digest-wrong-domain digest-plain-hash digest-lf-hash"),
        (.binding, "binding-transition binding-descriptor binding-nonce binding-expiry"),
    ]
    let pinnedReasons = Dictionary(uniqueKeysWithValues: families.flatMap { reason, ids in ids.split(separator: " ").map { (String($0), reason) } })
    try #require(Set(corpus.negatives.map(\.id)) == Set(pinnedReasons.keys))
    try #require(corpus.negatives.count == pinnedReasons.count)
    for vector in corpus.negatives {
        let reason = try #require(pinnedReasons[vector.id])
        #expect(vector.reason_class == reason.rawValue)
        let base = try #require(corpus.positives.first { $0.id == vector.base })
        #expect(vector.base == "intent-enroll1")
        #expect(vector.core_id == (reason == .binding ? "enroll1" : nil))
        #expect(vector.raw_hex != base.raw_hex || vector.sha256 != base.sha256)
        let bytes = try intentBytes(vector.raw_hex)
        if vector.id == "canonical-size-1024" { #expect(bytes.count == 1024) }
        if vector.id == "bounds-size-1025" { #expect(bytes.count == 1025) }
        if reason == .binding { #expect(vector.sha256 == intentDigest(bytes)) }
        #expect(throws: reason, "\(vector.id)") {
            _ = try validateIntent(bytes, digest: vector.sha256, coreID: vector.core_id, corpus: core)
        }
    }
}

@Test func registryIntentFixtureIntegrityPrecedesIntentValidation() throws {
    let corpus = try registryCorpus()
    #expect(throws: IntentFixtureError.unknownCore) {
        _ = try validateIntent(Data(), digest: "", coreID: "missing", corpus: corpus)
    }
    let coreData = try intentFixtureData("testdata/gate1a-registry/corpus.json")
    var document = try #require(JSONSerialization.jsonObject(with: coreData) as? [String: Any])
    var positives = try #require(document["positives"] as? [[String: Any]])
    positives[0]["request"] = "{}"
    document["positives"] = positives
    let corrupted = try JSONDecoder().decode(RegistryCorpus.self, from: JSONSerialization.data(withJSONObject: document))
    // enroll1 is both a direct core and a signed prefix of rotate2.
    for id in ["enroll1", "rotate2"] {
        #expect(throws: IntentFixtureError.invalidCore) {
            _ = try validateIntent(Data(), digest: "", coreID: id, corpus: corrupted)
        }
    }
}
