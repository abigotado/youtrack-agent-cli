import enum CryptoKit.P256
import struct Foundation.Data

enum RegistrySignatureControlError: Error, Equatable {
  case invalidSignature
  case invalidPublicKey
}

private let registrySignatureControlOrder: [UInt8] = [
  0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]

func registrySignatureControlTwin(raw: Data) throws -> Data {
  let scalars = Array(raw)
  guard scalars.count == 64 else { throw RegistrySignatureControlError.invalidSignature }
  for scalar in [scalars.prefix(32), scalars.suffix(32)] {
    guard scalar.contains(where: { $0 != 0 }),
      scalar.lexicographicallyPrecedes(registrySignatureControlOrder)
    else { throw RegistrySignatureControlError.invalidSignature }
  }
  var twin = scalars
  var borrow = 0
  for index in (0..<32).reversed() {
    let difference = Int(registrySignatureControlOrder[index]) - Int(scalars[index + 32]) - borrow
    twin[index + 32] = UInt8(difference & 255)
    borrow = difference < 0 ? 1 : 0
  }
  return Data(twin)
}

// Mathematical test control, independent of production codecs and verdicts.
// Native rejection permits only the equivalent (r, N-s), with the same key and
// message. High-S acceptance here never changes strict production ingress.
func registrySignatureControl(message: Data, derSignature: Data, x963: Data) throws -> Bool {
  guard (8...72).contains(derSignature.count) else {
    throw RegistrySignatureControlError.invalidSignature
  }
  let signature: P256.Signing.ECDSASignature
  do {
    signature = try P256.Signing.ECDSASignature(derRepresentation: derSignature)
  } catch {
    throw RegistrySignatureControlError.invalidSignature
  }
  guard signature.derRepresentation == derSignature else {
    throw RegistrySignatureControlError.invalidSignature
  }
  let twin = try registrySignatureControlTwin(raw: signature.rawRepresentation)
  guard x963.count == 65, x963.first == 0x04 else {
    throw RegistrySignatureControlError.invalidPublicKey
  }
  let key: P256.Signing.PublicKey
  do {
    key = try P256.Signing.PublicKey(x963Representation: x963)
  } catch {
    throw RegistrySignatureControlError.invalidPublicKey
  }
  guard key.x963Representation == x963 else {
    throw RegistrySignatureControlError.invalidPublicKey
  }
  if key.isValidSignature(signature, for: message) { return true }

  let equivalent: P256.Signing.ECDSASignature
  do {
    equivalent = try P256.Signing.ECDSASignature(rawRepresentation: twin)
  } catch {
    return false
  }
  return key.isValidSignature(equivalent, for: message)
}
