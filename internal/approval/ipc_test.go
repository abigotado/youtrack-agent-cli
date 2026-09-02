package approval

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

func TestGate1APlanAndIPCSharedFixtures(t *testing.T) {
	for _, name := range []string{"plan-issue-create.json", "plan-issue-update.json", "plan-comment-add.json"} {
		t.Run(name, func(t *testing.T) {
			raw := gate1AFixture(t, name)
			snapshot, err := ValidatePlanSnapshot(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(snapshot.Bytes(), raw) {
				t.Fatal("validated snapshot did not retain exact canonical bytes")
			}
		})
	}

	var challenge [IPCChallengeBytes]byte
	for index := range challenge {
		challenge[index] = byte(index)
	}
	planBytes := gate1AFixture(t, "plan-comment-add.json")
	requestFixture := mustDecodeHex(t, gate1AFixture(t, "ipc-request.hex"))
	requestBytes, err := EncodeIPCRequest(challenge, planBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(requestBytes, requestFixture) {
		t.Fatal("encoded request differs from shared frame fixture")
	}
	request, snapshot, err := DecodeIPCRequest(requestFixture)
	if err != nil {
		t.Fatal(err)
	}
	if request.Challenge != challenge || !bytes.Equal(request.PlanBytes, planBytes) {
		t.Fatal("decoded request differs from exact fixture values")
	}

	successFixture := mustDecodeHex(t, gate1AFixture(t, "ipc-success.hex"))
	response, err := DecodeIPCResponse(successFixture)
	if err != nil {
		t.Fatal(err)
	}
	if response.Success == nil || response.Failure != nil {
		t.Fatalf("decoded response = %#v, want success-only union", response)
	}
	receipt, err := ValidateIPCSuccess(*response.Success, challenge, snapshot, time.Date(2026, 9, 2, 15, 35, 56, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := snapshot.Plan()
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PlanID != plan.PlanID {
		t.Fatalf("receipt plan ID = %q, want %q", receipt.PlanID, plan.PlanID)
	}

	errorFixture := mustDecodeHex(t, gate1AFixture(t, "ipc-error.hex"))
	response, err = DecodeIPCResponse(errorFixture)
	if err != nil {
		t.Fatal(err)
	}
	if response.Failure == nil || response.Success != nil || response.Failure.Code != IPCErrorUserCanceled {
		t.Fatalf("decoded response = %#v, want user-canceled failure-only union", response)
	}
	if err := ValidateIPCFailure(*response.Failure, challenge); err != nil {
		t.Fatal(err)
	}
}

func TestIPCFrameRejectsHeaderLengthAndUnionTampering(t *testing.T) {
	valid := mustDecodeHex(t, gate1AFixture(t, "ipc-error.hex"))
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "truncated header", mutate: func(raw []byte) []byte { return raw[:IPCHeaderBytes-1] }},
		{name: "magic", mutate: func(raw []byte) []byte { raw[0] ^= 1; return raw }},
		{name: "version", mutate: func(raw []byte) []byte { raw[8]++; return raw }},
		{name: "unknown kind", mutate: func(raw []byte) []byte { raw[9] = 4; return raw }},
		{name: "reserved", mutate: func(raw []byte) []byte { raw[11] = 1; return raw }},
		{name: "declared oversized before payload allocation", mutate: func(raw []byte) []byte {
			binary.BigEndian.PutUint32(raw[12:16], exactIPCErrorPayload+1)
			return raw[:IPCHeaderBytes]
		}},
		{name: "trailing", mutate: func(raw []byte) []byte { return append(raw, 0) }},
		{name: "invalid closed error code", mutate: func(raw []byte) []byte { raw[len(raw)-1] = 7; return raw }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.mutate(append([]byte(nil), valid...))
			if _, err := DecodeIPCResponse(raw); err == nil {
				t.Fatal("DecodeIPCResponse() accepted tampered frame")
			}
		})
	}

	requestPayload := bytes.Repeat([]byte{1}, minimumRequestPayload)
	requestFrame, err := EncodeIPCFrame(IPCFrameRequest, requestPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeIPCResponse(requestFrame); err == nil {
		t.Fatal("DecodeIPCResponse() accepted request kind")
	}
}

func TestValidateIPCResponseCrossBindings(t *testing.T) {
	var challenge [IPCChallengeBytes]byte
	for index := range challenge {
		challenge[index] = byte(index)
	}
	snapshot, err := ValidatePlanSnapshot(gate1AFixture(t, "plan-comment-add.json"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := DecodeIPCResponse(mustDecodeHex(t, gate1AFixture(t, "ipc-success.hex")))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 15, 35, 56, 0, time.UTC)

	t.Run("challenge", func(t *testing.T) {
		wrong := challenge
		wrong[0] ^= 1
		if _, err := ValidateIPCSuccess(*response.Success, wrong, snapshot, now); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted the wrong challenge")
		}
	})
	t.Run("snapshot bytes", func(t *testing.T) {
		tampered := snapshot
		tampered.bytes = append([]byte(nil), tampered.bytes...)
		tampered.bytes[len(tampered.bytes)-1] ^= 1
		if _, err := ValidateIPCSuccess(*response.Success, challenge, tampered, now); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted changed snapshot bytes")
		}
	})
	t.Run("fingerprint", func(t *testing.T) {
		receipt := append([]byte(nil), response.Success.ReceiptJSON...)
		needle := []byte(`"key_fingerprint_sha256":"5`)
		index := bytes.Index(receipt, needle)
		if index < 0 {
			t.Fatal("fingerprint not found in fixture")
		}
		receipt[index+len(needle)-1] = '6'
		tampered := *response.Success
		tampered.ReceiptJSON = receipt
		if _, err := ValidateIPCSuccess(tampered, challenge, snapshot, now); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted changed fingerprint")
		}
	})
	t.Run("expired", func(t *testing.T) {
		if _, err := ValidateIPCSuccess(*response.Success, challenge, snapshot, time.Date(2026, 9, 2, 15, 36, 56, 0, time.UTC)); err == nil {
			t.Fatal("ValidateIPCSuccess() accepted expiry boundary")
		}
	})

	failure := IPCFailure{Challenge: challenge, Code: IPCErrorUserCanceled}
	wrong := challenge
	wrong[len(wrong)-1] ^= 1
	if err := ValidateIPCFailure(failure, wrong); err == nil {
		t.Fatal("ValidateIPCFailure() accepted the wrong challenge")
	}
	failure.Code = 0
	if err := ValidateIPCFailure(failure, challenge); err == nil {
		t.Fatal("ValidateIPCFailure() accepted an open-ended error code")
	}
}

func TestEncodeIPCFrameKindSpecificBounds(t *testing.T) {
	tests := []struct {
		name    string
		kind    IPCFrameKind
		length  int
		wantErr bool
	}{
		{name: "request minimum", kind: IPCFrameRequest, length: minimumRequestPayload},
		{name: "request maximum", kind: IPCFrameRequest, length: maxIPCRequestPayload},
		{name: "request empty plan", kind: IPCFrameRequest, length: minimumRequestPayload - 1, wantErr: true},
		{name: "request over maximum", kind: IPCFrameRequest, length: maxIPCRequestPayload + 1, wantErr: true},
		{name: "success minimum", kind: IPCFrameSuccess, length: minimumSuccessPayload},
		{name: "success maximum", kind: IPCFrameSuccess, length: maxIPCSuccessPayload},
		{name: "success empty receipt", kind: IPCFrameSuccess, length: minimumSuccessPayload - 1, wantErr: true},
		{name: "error exact", kind: IPCFrameError, length: exactIPCErrorPayload},
		{name: "error over", kind: IPCFrameError, length: exactIPCErrorPayload + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeIPCFrame(tt.kind, make([]byte, tt.length))
			if (err != nil) != tt.wantErr {
				t.Fatalf("EncodeIPCFrame(kind=%d,len=%d) error = %v, wantErr %v", tt.kind, tt.length, err, tt.wantErr)
			}
		})
	}
}

func TestIPCFixtureHexIsCanonical(t *testing.T) {
	for _, name := range []string{"ipc-request.hex", "ipc-success.hex", "ipc-error.hex"} {
		raw := gate1AFixture(t, name)
		decoded := make([]byte, hex.DecodedLen(len(raw)))
		count, err := hex.Decode(decoded, raw)
		if err != nil || hex.EncodeToString(decoded[:count]) != string(raw) {
			t.Fatalf("fixture %s is not canonical lowercase hex: %v", name, err)
		}
	}
}
