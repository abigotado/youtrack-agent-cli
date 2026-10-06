package approval

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

type registrySignatureControl struct {
	SchemaVersion int    `json:"schema_version"`
	Scope         string `json:"scope"`
	PublicScalar  int    `json:"public_scalar"`
	MessageHex    string `json:"message_hex"`
	MessageLength int    `json:"message_length"`
	MessageSHA256 string `json:"message_sha256"`
	SPKIHex       string `json:"spki_hex"`
	X963Hex       string `json:"x963_hex"`
	WrongX963Hex  string `json:"wrong_x963_hex"`
	LowDERHex     string `json:"low_der_hex"`
	HighDERHex    string `json:"high_der_hex"`
	LowRawHex     string `json:"low_raw_hex"`
	HighRawHex    string `json:"high_raw_hex"`
}

type registrySignatureControlRS struct {
	R, S *big.Int
}

func readRegistrySignatureControl(t *testing.T) registrySignatureControl {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate1a-registry", "signature-control.json"))
	if err != nil {
		t.Fatal(err)
	}
	var control registrySignatureControl
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&control); err != nil {
		t.Fatal(err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatal("trailing signature control data")
	}
	if control.SchemaVersion != 1 || control.Scope != "registry-signature-control" || control.PublicScalar != 9 {
		t.Fatal("signature control schema or public scalar differs from literal expectation")
	}
	if control.MessageLength != 1795 || control.MessageSHA256 != "0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba" {
		t.Fatal("signature control message metadata differs from literal expectation")
	}
	return control
}

func registrySignatureControlHex(t *testing.T, encoded string, length int) []byte {
	t.Helper()
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != length || hex.EncodeToString(raw) != encoded {
		t.Fatal("signature control hex is not canonical or has the wrong length")
	}
	return raw
}

func registrySignatureControlDER(t *testing.T, der, raw []byte) registrySignatureControlRS {
	t.Helper()
	var signature registrySignatureControlRS
	rest, err := asn1.Unmarshal(der, &signature)
	if err != nil || len(rest) != 0 || signature.R == nil || signature.S == nil {
		t.Fatal("signature control DER does not contain one integer pair")
	}
	canonical, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(canonical, der) {
		t.Fatal("signature control DER is not canonical")
	}
	order := elliptic.P256().Params().N
	for _, component := range []*big.Int{signature.R, signature.S} {
		if component.Sign() <= 0 || component.Cmp(order) >= 0 {
			t.Fatal("signature control integer is outside the P-256 range")
		}
	}
	wantRaw := make([]byte, 64)
	signature.R.FillBytes(wantRaw[:32])
	signature.S.FillBytes(wantRaw[32:])
	if !bytes.Equal(raw, wantRaw) {
		t.Fatal("signature control raw representation differs from its DER integers")
	}
	return signature
}

// Independent standard-library verification of public test data. In particular,
// the high-S twin must reach cryptographic verification without the registry's
// production low-S grammar rejecting it first.
func TestSharedRegistrySignatureControl(t *testing.T) {
	control := readRegistrySignatureControl(t)
	message := registrySignatureControlHex(t, control.MessageHex, 1795)
	digest := sha256.Sum256(message)
	if hex.EncodeToString(digest[:]) != "0d76c17d481b96dcfb6c8bcf2ff3fae316858e0b0f6af5db7c3519eb655835ba" {
		t.Fatal("signature control message digest differs from literal expectation")
	}
	spki := registrySignatureControlHex(t, control.SPKIHex, 91)
	parsed, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		t.Fatal("signature control SPKI is not P-256")
	}
	x963 := registrySignatureControlHex(t, control.X963Hex, 65)
	curve := elliptic.P256()
	var scalarNine [32]byte
	scalarNine[31] = 9
	knownKey, err := ecdh.P256().NewPrivateKey(scalarNine[:])
	if err != nil {
		t.Fatal(err)
	}
	parsedPoint, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x963, parsedPoint) || !bytes.Equal(x963, knownKey.PublicKey().Bytes()) {
		t.Fatal("signature control SPKI and X9.63 do not represent the literal public 9G point")
	}
	wrongX963 := registrySignatureControlHex(t, control.WrongX963Hex, 65)
	var scalarOne [32]byte
	scalarOne[31] = 1
	knownWrongKey, err := ecdh.P256().NewPrivateKey(scalarOne[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wrongX963, x963) || !bytes.Equal(wrongX963, knownWrongKey.PublicKey().Bytes()) {
		t.Fatal("signature control wrong public point is not the distinct literal 1G point")
	}
	wrongKey, err := ecdsa.ParseUncompressedPublicKey(curve, wrongX963)
	if err != nil {
		t.Fatal(err)
	}
	lowDER, err := hex.DecodeString(control.LowDERHex)
	if err != nil || len(lowDER) == 0 || hex.EncodeToString(lowDER) != control.LowDERHex {
		t.Fatal("signature control low-S DER hex is not canonical")
	}
	highDER, err := hex.DecodeString(control.HighDERHex)
	if err != nil || len(highDER) == 0 || hex.EncodeToString(highDER) != control.HighDERHex {
		t.Fatal("signature control high-S DER hex is not canonical")
	}
	lowRaw := registrySignatureControlHex(t, control.LowRawHex, 64)
	highRaw := registrySignatureControlHex(t, control.HighRawHex, 64)
	low := registrySignatureControlDER(t, lowDER, lowRaw)
	high := registrySignatureControlDER(t, highDER, highRaw)
	order := curve.Params().N
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if low.R.Cmp(high.R) != 0 || low.S.Cmp(halfOrder) > 0 || high.S.Cmp(halfOrder) <= 0 || high.S.Cmp(new(big.Int).Sub(order, low.S)) != 0 {
		t.Fatal("signature controls are not exact low-S and high-S twins")
	}
	changedMessage := append([]byte{}, message...)
	changedMessage[0] ^= 1
	wrongDigest := sha256.Sum256(changedMessage)
	for _, form := range []struct {
		name      string
		der, raw  []byte
		signature registrySignatureControlRS
	}{
		{"low-s", lowDER, lowRaw, low},
		{"high-s", highDER, highRaw, high},
	} {
		t.Run(form.name, func(t *testing.T) {
			wrongR := new(big.Int).Add(form.signature.R, big.NewInt(1))
			if wrongR.Cmp(order) >= 0 {
				wrongR.SetInt64(1)
			}
			wrongS := new(big.Int).Set(form.signature.S)
			for {
				wrongS.Add(wrongS, big.NewInt(1))
				if wrongS.Cmp(order) >= 0 {
					wrongS.SetInt64(1)
				}
				if wrongS.Cmp(low.S) != 0 && wrongS.Cmp(high.S) != 0 {
					break
				}
			}
			for _, test := range []struct {
				name      string
				key       *ecdsa.PublicKey
				digest    [32]byte
				signature registrySignatureControlRS
				accepted  bool
			}{
				{"valid", key, digest, form.signature, true},
				{"wrong-message", key, wrongDigest, form.signature, false},
				{"wrong-key", wrongKey, digest, form.signature, false},
				{"wrong-r", key, digest, registrySignatureControlRS{wrongR, form.signature.S}, false},
				{"wrong-s", key, digest, registrySignatureControlRS{form.signature.R, wrongS}, false},
			} {
				t.Run(test.name, func(t *testing.T) {
					der, err := asn1.Marshal(test.signature)
					if err != nil {
						t.Fatal(err)
					}
					raw := make([]byte, 64)
					test.signature.R.FillBytes(raw[:32])
					test.signature.S.FillBytes(raw[32:])
					registrySignatureControlDER(t, der, raw)
					if test.name == "valid" && (!bytes.Equal(der, form.der) || !bytes.Equal(raw, form.raw)) {
						t.Fatal("positive control does not use the fixture signature bytes")
					}
					if accepted := ecdsa.VerifyASN1(test.key, test.digest[:], der); accepted != test.accepted {
						t.Fatalf("DER verification accepted=%v, want %v", accepted, test.accepted)
					}
					if accepted := ecdsa.Verify(test.key, test.digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])); accepted != test.accepted {
						t.Fatalf("raw integer verification accepted=%v, want %v", accepted, test.accepted)
					}
				})
			}
		})
	}
}

func TestSharedRegistrySignatureControlProductionLowSIngress(t *testing.T) {
	control := readRegistrySignatureControl(t)
	for _, test := range []struct {
		name, derHex string
		accepted     bool
	}{
		{"low-s", control.LowDERHex, true},
		{"high-s", control.HighDERHex, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			der, err := hex.DecodeString(test.derHex)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateP256DERSignature(der); (err == nil) != test.accepted {
				t.Fatalf("production DER grammar accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
			encoded := base64.RawURLEncoding.EncodeToString(der)
			decoded, err := DecodeP256DERSignature(encoded)
			if (err == nil) != test.accepted {
				t.Fatalf("production base64url ingress accepted=%v, want %v: %v", err == nil, test.accepted, err)
			}
			if test.accepted {
				if !bytes.Equal(decoded, der) || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
					t.Fatal("production low-S ingress changed the canonical fixture signature")
				}
			} else if len(decoded) != 0 {
				t.Fatal("production high-S refusal returned signature bytes")
			}
		})
	}
}
