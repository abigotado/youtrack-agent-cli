# Gate 1A cross-language fixtures

Each text file ends in one source-control LF. Tests remove exactly that final
LF before comparing protocol bytes or decoding hex/base64url.

- `signing.json` is the exact unsigned receipt from `approval.SigningBytes`.
- `receipt.json` is the exact signed receipt from `approval.ReceiptBytes`.
- Their `.sha256` files digest the protocol bytes without the fixture LF.
- `signature.der.hex` encodes the strict structural vector `r=1, s=2` and
  `signature.base64url` is its unpadded base64url form. It is a codec vector,
  not a signature over `signing.json`.
- The public-key X9.63 vector is the P-256 generator point. The SPKI and
  fingerprint files pin its exact protocol-v1 encodings.
- `display.hex` contains inert JSON-like untrusted content, while
  `display.escaped.txt` encodes it with the frozen byte-preserving renderer.
