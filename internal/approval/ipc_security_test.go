package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/asn1"
	"encoding/binary"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIPCFrameEveryKindRejectsTruncationTrailingAndImpossibleLengths(t *testing.T) {
	fixtures := []struct {
		name string
		kind IPCFrameKind
		raw  []byte
		min  uint32
		max  uint32
	}{
		{name: "request", kind: IPCFrameRequest, raw: mustDecodeHex(t, gate1AFixture(t, "ipc-request.hex")), min: minimumRequestPayload, max: maxIPCRequestPayload},
		{name: "success", kind: IPCFrameSuccess, raw: mustDecodeHex(t, gate1AFixture(t, "ipc-success.hex")), min: minimumSuccessPayload, max: maxIPCSuccessPayload},
		{name: "error", kind: IPCFrameError, raw: mustDecodeHex(t, gate1AFixture(t, "ipc-error.hex")), min: exactIPCErrorPayload, max: exactIPCErrorPayload},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			for name, raw := range map[string][]byte{
				"truncated payload":  fixture.raw[:len(fixture.raw)-1],
				"trailing payload":   append(append([]byte(nil), fixture.raw...), 0),
				"declared under min": ipcHeaderForTest(fixture.kind, fixture.min-1),
				"declared over max":  ipcHeaderForTest(fixture.kind, fixture.max+1),
			} {
				t.Run(name, func(t *testing.T) {
					if _, err := DecodeIPCFrame(raw); err == nil {
						t.Fatal("DecodeIPCFrame() accepted malformed per-kind length")
					}
				})
			}
		})
	}

	for _, kind := range []IPCFrameKind{IPCFrameRequest, IPCFrameSuccess, IPCFrameError, 0, 255} {
		if err := validateIPCPayloadLength(kind, math.MaxUint64); err == nil {
			t.Fatalf("validateIPCPayloadLength(kind=%d, MaxUint64) accepted impossible length", kind)
		}
	}
}

func TestIPCClosedErrorUnionAndChallengeBinding(t *testing.T) {
	challenge := ipcChallengeForTest()
	for code := IPCErrorUserCanceled; code <= IPCErrorInternalFailure; code++ {
		t.Run(codeNameForTest(code), func(t *testing.T) {
			raw, err := EncodeIPCFailure(IPCFailure{Challenge: challenge, Code: code})
			if err != nil {
				t.Fatal(err)
			}
			response, err := DecodeIPCResponse(raw)
			if err != nil {
				t.Fatal(err)
			}
			if response.Success != nil || response.Failure == nil || response.Failure.Code != code {
				t.Fatalf("decoded union = %#v, want only error code %d", response, code)
			}
			if err := ValidateIPCFailure(*response.Failure, challenge); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, code := range []IPCErrorCode{0, IPCErrorInternalFailure + 1, 255} {
		if _, err := EncodeIPCFailure(IPCFailure{Challenge: challenge, Code: code}); err == nil {
			t.Fatalf("EncodeIPCFailure() accepted open error code %d", code)
		}
	}

	valid := IPCFailure{Challenge: challenge, Code: IPCErrorUserCanceled}
	for _, index := range []int{0, IPCChallengeBytes / 2, IPCChallengeBytes - 1} {
		wrong := challenge
		wrong[index] ^= 0xff
		if subtle.ConstantTimeCompare(challenge[:], wrong[:]) != 0 {
			t.Fatalf("test challenge mismatch at byte %d was ineffective", index)
		}
		if err := ValidateIPCFailure(valid, wrong); err == nil {
			t.Fatalf("ValidateIPCFailure() accepted challenge mismatch at byte %d", index)
		}
	}
}

func TestValidatedPlanSnapshotAndDecodedFramesOwnTheirBytes(t *testing.T) {
	raw := append([]byte(nil), gate1AFixture(t, "plan-comment-add.json")...)
	want := append([]byte(nil), raw...)
	snapshot, err := ValidatePlanSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if !bytes.Equal(snapshot.Bytes(), want) {
		t.Fatal("validated snapshot aliases caller-owned plan bytes")
	}
	returnedBytes := snapshot.Bytes()
	returnedBytes[0] ^= 1
	if !bytes.Equal(snapshot.Bytes(), want) {
		t.Fatal("validated snapshot aliases returned plan bytes")
	}
	returnedPlan, err := snapshot.Plan()
	if err != nil {
		t.Fatal(err)
	}
	returnedPlan.PlanID = "YTAP-77777777777777777777777774"
	unchangedPlan, err := snapshot.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if returnedPlan.PlanID == unchangedPlan.PlanID {
		t.Fatal("validated snapshot aliases returned plan values")
	}

	frameRaw := mustDecodeHex(t, gate1AFixture(t, "ipc-error.hex"))
	frame, err := DecodeIPCFrame(frameRaw)
	if err != nil {
		t.Fatal(err)
	}
	wantPayload := append([]byte(nil), frame.Payload...)
	frameRaw[IPCHeaderBytes] ^= 1
	if !bytes.Equal(frame.Payload, wantPayload) {
		t.Fatal("decoded frame payload aliases caller-owned frame bytes")
	}
}

func TestValidateIPCSuccessCryptographicallyBindsEveryReceiptField(t *testing.T) {
	challenge := ipcChallengeForTest()
	snapshot, err := ValidatePlanSnapshot(gate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)
	success, key := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
	if _, err := ValidateIPCSuccess(success, challenge, snapshot, issued.Add(time.Minute)); err != nil {
		t.Fatalf("valid cross-bound success: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Receipt)
	}{
		{name: "plan ID", mutate: func(r *Receipt) { r.PlanID = "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA" }},
		{name: "plan digest", mutate: func(r *Receipt) { r.PlanSHA256 = strings.Repeat("f", 64) }},
		{name: "profile identity", mutate: func(r *Receipt) { r.ProfileIdentitySHA256 = strings.Repeat("f", 64) }},
		{name: "account", mutate: func(r *Receipt) { r.AccountID = "9-9" }},
		{name: "project ID", mutate: func(r *Receipt) { r.ProjectID = "9-9" }},
		{name: "project key", mutate: func(r *Receipt) { r.ProjectKey = "OTHER" }},
		{name: "schema", mutate: func(r *Receipt) { r.SchemaSHA256 = strings.Repeat("f", 64) }},
		{name: "request", mutate: func(r *Receipt) { r.RequestSHA256 = strings.Repeat("f", 64) }},
		{name: "expected", mutate: func(r *Receipt) { r.ExpectedSHA256 = strings.Repeat("f", 64) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt, parseErr := ParseReceiptBytes(success.ReceiptJSON)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			tt.mutate(&receipt)
			resignReceiptForTest(t, &receipt, key, nil)
			receiptJSON, encodeErr := ReceiptBytes(receipt)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			tampered := success
			tampered.ReceiptJSON = receiptJSON
			if _, validateErr := ValidateIPCSuccess(tampered, challenge, snapshot, issued.Add(time.Minute)); validateErr == nil {
				t.Fatal("ValidateIPCSuccess() accepted a validly signed receipt for different bindings")
			}
		})
	}
}

func TestValidateIPCSuccessRejectsWrongKeyWrongMessageAndTTLBoundaries(t *testing.T) {
	challenge := ipcChallengeForTest()
	snapshot, err := ValidatePlanSnapshot(gate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 9, 2, 15, 34, 56, 0, time.UTC)

	t.Run("exact maximum TTL and future skew accepted", func(t *testing.T) {
		success, _ := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(MaximumReceiptTTL), nil)
		if _, err := ValidateIPCSuccess(success, challenge, snapshot, issued.Add(-defaultClockSkew)); err != nil {
			t.Fatalf("exact protocol boundaries rejected: %v", err)
		}
	})
	t.Run("one second beyond future skew", func(t *testing.T) {
		success, _ := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
		if _, err := ValidateIPCSuccess(success, challenge, snapshot, issued.Add(-defaultClockSkew-time.Second)); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted issue time beyond future skew")
		}
	})
	t.Run("expiry instant", func(t *testing.T) {
		success, _ := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
		if _, err := ValidateIPCSuccess(success, challenge, snapshot, issued.Add(2*time.Minute)); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted the expiry instant")
		}
	})
	t.Run("wrong signing key with matching fingerprint", func(t *testing.T) {
		original, originalKey := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
		wrongKey, generateErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if generateErr != nil {
			t.Fatal(generateErr)
		}
		wrongSPKI := spkiForKeyForTest(t, &wrongKey.PublicKey)
		wrongFingerprint, fingerprintErr := P256SPKIFingerprintSHA256(wrongSPKI)
		if fingerprintErr != nil {
			t.Fatal(fingerprintErr)
		}
		receipt, parseErr := ParseReceiptBytes(original.ReceiptJSON)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		receipt.KeyFingerprintSHA256 = wrongFingerprint
		resignReceiptForTest(t, &receipt, originalKey, nil)
		receiptJSON, encodeErr := ReceiptBytes(receipt)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		original.SPKIDER = wrongSPKI
		original.ReceiptJSON = receiptJSON
		if _, validateErr := ValidateIPCSuccess(original, challenge, snapshot, issued.Add(time.Minute)); validateErr == nil {
			t.Fatal("ValidateIPCSuccess() accepted signature from a key other than the response identity")
		}
	})
	t.Run("wrong signed message", func(t *testing.T) {
		success, key := signedIPCSuccessForTest(t, snapshot, challenge, issued, issued.Add(2*time.Minute), nil)
		receipt, parseErr := ParseReceiptBytes(success.ReceiptJSON)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		resignReceiptForTest(t, &receipt, key, []byte("different message"))
		receiptJSON, encodeErr := ReceiptBytes(receipt)
		if encodeErr != nil {
			t.Fatal(encodeErr)
		}
		success.ReceiptJSON = receiptJSON
		if _, validateErr := ValidateIPCSuccess(success, challenge, snapshot, issued.Add(time.Minute)); validateErr == nil {
			t.Fatal("ValidateIPCSuccess() accepted signature over different bytes")
		}
	})
}

func signedIPCSuccessForTest(t *testing.T, snapshot ValidatedPlanSnapshot, challenge [IPCChallengeBytes]byte, issued, expires time.Time, key *ecdsa.PrivateKey) (IPCSuccess, *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	spki := spkiForKeyForTest(t, &key.PublicKey)
	fingerprint, err := P256SPKIFingerprintSHA256(spki)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := snapshot.Plan()
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion,
		ReceiptID:     "YTAR-AAAQEAYEAUDAOCAJBIFQYDIOB4", Nonce: "YTAN-6DQNBQFQUCIIA4DAKBADAIAQAA",
		PlanID: plan.PlanID, PlanSHA256: plan.IntentSHA256,
		ProfileIdentitySHA256: plan.Profile.IdentitySHA256, AccountID: plan.Profile.Account.ID,
		ProjectID: plan.Policy.Project.ID, ProjectKey: plan.Policy.Project.Key,
		SchemaSHA256: plan.Policy.SchemaSHA256, RequestSHA256: plan.RequestSHA256,
		ExpectedSHA256: plan.ExpectedSHA256, IssuedAt: issued, ExpiresAt: expires,
		KeyGeneration: "test-1", KeyFingerprintSHA256: fingerprint,
	}
	resignReceiptForTest(t, &receipt, key, nil)
	receiptJSON, err := ReceiptBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return IPCSuccess{Challenge: challenge, SPKIDER: spki, ReceiptJSON: receiptJSON}, key
}

func resignReceiptForTest(t *testing.T, receipt *Receipt, key *ecdsa.PrivateKey, overrideMessage []byte) {
	t.Helper()
	message := overrideMessage
	if message == nil {
		var err error
		message, err = SigningBytes(*receipt)
		if err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(key.Curve.Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(key.Curve.Params().N, s)
	}
	der, err := asn1.Marshal(p256Signature{R: r, S: s})
	if err != nil {
		t.Fatal(err)
	}
	receipt.Signature, err = EncodeP256DERSignature(der)
	if err != nil {
		t.Fatal(err)
	}
}

func spkiForKeyForTest(t *testing.T, key *ecdsa.PublicKey) []byte {
	t.Helper()
	x963 := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	spki, err := P256X963ToDERSPKI(x963)
	if err != nil {
		t.Fatal(err)
	}
	return spki
}

func ipcHeaderForTest(kind IPCFrameKind, length uint32) []byte {
	header := make([]byte, IPCHeaderBytes)
	copy(header, ipcMagic)
	header[8] = IPCVersion
	header[9] = byte(kind)
	binary.BigEndian.PutUint32(header[12:], length)
	return header
}

func ipcChallengeForTest() [IPCChallengeBytes]byte {
	var challenge [IPCChallengeBytes]byte
	for index := range challenge {
		challenge[index] = byte(index)
	}
	return challenge
}

func codeNameForTest(code IPCErrorCode) string {
	return "code-" + strconv.Itoa(int(code))
}
