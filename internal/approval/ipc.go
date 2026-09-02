package approval

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

const (
	IPCHeaderBytes          = 16
	IPCChallengeBytes       = 32
	IPCVersion        uint8 = 1
	MaxIPCPlanBytes         = intent.MaxCanonicalPlanBytes

	ipcMagic              = "YTAPIPC\x00"
	ipcSPKIBytes          = p256DERSPKIBytes
	maxIPCRequestPayload  = IPCChallengeBytes + MaxIPCPlanBytes
	maxIPCSuccessPayload  = IPCChallengeBytes + ipcSPKIBytes + MaxReceiptBytes
	exactIPCErrorPayload  = IPCChallengeBytes + 1
	minimumRequestPayload = IPCChallengeBytes + 1
	minimumSuccessPayload = IPCChallengeBytes + ipcSPKIBytes + 1
)

// IPCFrameKind identifies one protocol-v1 frame payload.
type IPCFrameKind uint8

const (
	IPCFrameRequest IPCFrameKind = 1
	IPCFrameSuccess IPCFrameKind = 2
	IPCFrameError   IPCFrameKind = 3
)

// IPCErrorCode is the complete closed helper-error vocabulary.
type IPCErrorCode uint8

const (
	IPCErrorUserCanceled            IPCErrorCode = 1
	IPCErrorRequestInvalid          IPCErrorCode = 2
	IPCErrorUserPresenceUnavailable IPCErrorCode = 3
	IPCErrorKeyUnavailable          IPCErrorCode = 4
	IPCErrorSigningFailed           IPCErrorCode = 5
	IPCErrorInternalFailure         IPCErrorCode = 6
)

// IPCFrame is one decoded, bounded frame. Payload owns its bytes.
type IPCFrame struct {
	Kind    IPCFrameKind
	Payload []byte
}

// IPCRequest carries the opaque challenge and exact canonical plan bytes.
type IPCRequest struct {
	Challenge [IPCChallengeBytes]byte
	PlanBytes []byte
}

// IPCSuccess carries the echoed challenge, exact P-256 SPKI, and canonical
// signed receipt bytes.
type IPCSuccess struct {
	Challenge   [IPCChallengeBytes]byte
	SPKIDER     []byte
	ReceiptJSON []byte
}

// IPCFailure carries only the echoed challenge and a closed error code.
type IPCFailure struct {
	Challenge [IPCChallengeBytes]byte
	Code      IPCErrorCode
}

// IPCResponse is a strict success/error union.
type IPCResponse struct {
	Success *IPCSuccess
	Failure *IPCFailure
}

// ValidatedPlanSnapshot binds parsed plan semantics to the exact immutable
// canonical bytes displayed and hashed by the helper.
type ValidatedPlanSnapshot struct {
	bytes []byte
}

// Bytes returns a defensive copy of the exact validated canonical bytes.
func (snapshot ValidatedPlanSnapshot) Bytes() []byte {
	return append([]byte(nil), snapshot.bytes...)
}

// Plan returns a freshly decoded copy of the validated plan. The snapshot's
// private byte authority cannot be changed through the returned value.
func (snapshot ValidatedPlanSnapshot) Plan() (intent.Plan, error) {
	return intent.ParseApprovalSnapshot(snapshot.bytes, MaxIPCPlanBytes)
}

// NewIPCChallenge returns a fresh opaque 256-bit challenge from crypto/rand.
func NewIPCChallenge() ([IPCChallengeBytes]byte, error) {
	var challenge [IPCChallengeBytes]byte
	if _, err := io.ReadFull(rand.Reader, challenge[:]); err != nil {
		return challenge, fmt.Errorf("allocate approval IPC challenge: %w", err)
	}
	return challenge, nil
}

// EncodeIPCFrame returns one exact frame with a 16-byte header and no trailing
// data. Per-kind payload bounds are checked before allocating the output.
func EncodeIPCFrame(kind IPCFrameKind, payload []byte) ([]byte, error) {
	if err := validateIPCPayloadLength(kind, uint64(len(payload))); err != nil {
		return nil, err
	}
	raw := make([]byte, IPCHeaderBytes+len(payload))
	copy(raw[:8], ipcMagic)
	raw[8] = IPCVersion
	raw[9] = byte(kind)
	// Bytes 10..11 are the reserved zero uint16.
	binary.BigEndian.PutUint32(raw[12:16], uint32(len(payload)))
	copy(raw[IPCHeaderBytes:], payload)
	return raw, nil
}

// DecodeIPCFrame accepts exactly one complete frame. It validates the uint32
// payload length against the kind-specific bound before copying any payload.
func DecodeIPCFrame(raw []byte) (IPCFrame, error) {
	if len(raw) < IPCHeaderBytes {
		return IPCFrame{}, fmt.Errorf("approval IPC frame header is truncated")
	}
	if string(raw[:8]) != ipcMagic || raw[8] != IPCVersion || raw[10] != 0 || raw[11] != 0 {
		return IPCFrame{}, fmt.Errorf("approval IPC frame header is invalid")
	}
	kind := IPCFrameKind(raw[9])
	length := binary.BigEndian.Uint32(raw[12:16])
	if err := validateIPCPayloadLength(kind, uint64(length)); err != nil {
		return IPCFrame{}, err
	}
	if uint64(len(raw)-IPCHeaderBytes) != uint64(length) {
		return IPCFrame{}, fmt.Errorf("approval IPC frame is truncated or has trailing bytes")
	}
	return IPCFrame{Kind: kind, Payload: append([]byte(nil), raw[IPCHeaderBytes:]...)}, nil
}

// EncodeIPCRequest validates and frames one canonical immutable plan snapshot.
func EncodeIPCRequest(challenge [IPCChallengeBytes]byte, planBytes []byte) ([]byte, error) {
	if _, err := ValidatePlanSnapshot(planBytes); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, IPCChallengeBytes+len(planBytes))
	payload = append(payload, challenge[:]...)
	payload = append(payload, planBytes...)
	return EncodeIPCFrame(IPCFrameRequest, payload)
}

// DecodeIPCRequest parses one strict request frame and validates its plan.
func DecodeIPCRequest(raw []byte) (IPCRequest, ValidatedPlanSnapshot, error) {
	frame, err := DecodeIPCFrame(raw)
	if err != nil {
		return IPCRequest{}, ValidatedPlanSnapshot{}, err
	}
	if frame.Kind != IPCFrameRequest {
		return IPCRequest{}, ValidatedPlanSnapshot{}, fmt.Errorf("approval IPC frame is not a request")
	}
	request := IPCRequest{PlanBytes: append([]byte(nil), frame.Payload[IPCChallengeBytes:]...)}
	copy(request.Challenge[:], frame.Payload[:IPCChallengeBytes])
	snapshot, err := ValidatePlanSnapshot(request.PlanBytes)
	if err != nil {
		return IPCRequest{}, ValidatedPlanSnapshot{}, err
	}
	return request, snapshot, nil
}

// EncodeIPCSuccess frames a strict success payload.
func EncodeIPCSuccess(success IPCSuccess) ([]byte, error) {
	if _, err := P256DERSPKIToX963(success.SPKIDER); err != nil {
		return nil, err
	}
	if _, err := ParseReceiptBytes(success.ReceiptJSON); err != nil {
		return nil, err
	}
	payload := make([]byte, 0, IPCChallengeBytes+len(success.SPKIDER)+len(success.ReceiptJSON))
	payload = append(payload, success.Challenge[:]...)
	payload = append(payload, success.SPKIDER...)
	payload = append(payload, success.ReceiptJSON...)
	return EncodeIPCFrame(IPCFrameSuccess, payload)
}

// EncodeIPCFailure frames a closed helper error without agent-controlled text.
func EncodeIPCFailure(failure IPCFailure) ([]byte, error) {
	if !failure.Code.valid() {
		return nil, fmt.Errorf("approval IPC error code is outside the closed vocabulary")
	}
	payload := make([]byte, exactIPCErrorPayload)
	copy(payload, failure.Challenge[:])
	payload[IPCChallengeBytes] = byte(failure.Code)
	return EncodeIPCFrame(IPCFrameError, payload)
}

// DecodeIPCResponse parses only the strict success/error union.
func DecodeIPCResponse(raw []byte) (IPCResponse, error) {
	frame, err := DecodeIPCFrame(raw)
	if err != nil {
		return IPCResponse{}, err
	}
	switch frame.Kind {
	case IPCFrameSuccess:
		success := &IPCSuccess{
			SPKIDER:     append([]byte(nil), frame.Payload[IPCChallengeBytes:IPCChallengeBytes+ipcSPKIBytes]...),
			ReceiptJSON: append([]byte(nil), frame.Payload[IPCChallengeBytes+ipcSPKIBytes:]...),
		}
		copy(success.Challenge[:], frame.Payload[:IPCChallengeBytes])
		if _, err := P256DERSPKIToX963(success.SPKIDER); err != nil {
			return IPCResponse{}, err
		}
		if _, err := ParseReceiptBytes(success.ReceiptJSON); err != nil {
			return IPCResponse{}, err
		}
		return IPCResponse{Success: success}, nil
	case IPCFrameError:
		failure := &IPCFailure{Code: IPCErrorCode(frame.Payload[IPCChallengeBytes])}
		copy(failure.Challenge[:], frame.Payload[:IPCChallengeBytes])
		if !failure.Code.valid() {
			return IPCResponse{}, fmt.Errorf("approval IPC error code is outside the closed vocabulary")
		}
		return IPCResponse{Failure: failure}, nil
	default:
		return IPCResponse{}, fmt.Errorf("approval IPC response cannot be a request")
	}
}

// ValidatePlanSnapshot strictly parses and re-encodes one canonical plan
// snapshot while retaining its exact immutable bytes.
func ValidatePlanSnapshot(raw []byte) (ValidatedPlanSnapshot, error) {
	if _, err := intent.ParseApprovalSnapshot(raw, MaxIPCPlanBytes); err != nil {
		return ValidatedPlanSnapshot{}, err
	}
	if err := ValidateApprovalDisplayBytes(raw); err != nil {
		return ValidatedPlanSnapshot{}, err
	}
	return ValidatedPlanSnapshot{bytes: append([]byte(nil), raw...)}, nil
}

// ValidateIPCSuccess cross-binds a success response to the request challenge,
// exact displayed snapshot, returned key, receipt lifetime, and signature.
func ValidateIPCSuccess(success IPCSuccess, expectedChallenge [IPCChallengeBytes]byte, snapshot ValidatedPlanSnapshot, now time.Time) (Receipt, error) {
	if subtle.ConstantTimeCompare(success.Challenge[:], expectedChallenge[:]) != 1 {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the helper response challenge does not match the request")
	}
	x963, err := P256DERSPKIToX963(success.SPKIDER)
	if err != nil {
		return Receipt{}, receiptError("RECEIPT_SIGNATURE_INVALID", "the helper response public key is invalid").Wrap(err)
	}
	receipt, err := ParseReceiptBytes(success.ReceiptJSON)
	if err != nil {
		return Receipt{}, err
	}
	fingerprint, err := P256SPKIFingerprintSHA256(success.SPKIDER)
	if err != nil {
		return Receipt{}, receiptError("RECEIPT_SIGNATURE_INVALID", "the helper response public-key fingerprint is invalid").Wrap(err)
	}
	if receipt.KeyFingerprintSHA256 != fingerprint {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the receipt does not bind the response public key")
	}
	if len(snapshot.bytes) == 0 {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the validated plan snapshot is empty")
	}
	plan, err := snapshot.Plan()
	if err != nil {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the validated plan snapshot is invalid").Wrap(err)
	}
	canonical, err := intent.ApprovalDisplayBytes(plan)
	if err != nil {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the validated plan snapshot is invalid").Wrap(err)
	}
	if !bytes.Equal(canonical, snapshot.bytes) {
		return Receipt{}, receiptError("RECEIPT_BINDING_MISMATCH", "the validated plan snapshot bytes changed")
	}
	publicKeyX, publicKeyY := elliptic.Unmarshal(elliptic.P256(), x963)
	if publicKeyX == nil || publicKeyY == nil {
		return Receipt{}, receiptError("RECEIPT_SIGNATURE_INVALID", "the helper response public key is invalid")
	}
	verifier := p256ReceiptSignatureVerifier{publicKey: &ecdsa.PublicKey{Curve: elliptic.P256(), X: publicKeyX, Y: publicKeyY}}
	if err := (BindingVerifier{
		Signatures: verifier,
		Now:        func() time.Time { return now },
		MaximumTTL: MaximumReceiptTTL,
		ClockSkew:  defaultClockSkew,
	}).Verify(context.Background(), plan, receipt); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// ValidateIPCFailure checks the echoed challenge in constant time and the
// closed error vocabulary. It never accepts helper-supplied text.
func ValidateIPCFailure(failure IPCFailure, expectedChallenge [IPCChallengeBytes]byte) error {
	if subtle.ConstantTimeCompare(failure.Challenge[:], expectedChallenge[:]) != 1 {
		return fmt.Errorf("approval IPC error challenge does not match the request")
	}
	if !failure.Code.valid() {
		return fmt.Errorf("approval IPC error code is outside the closed vocabulary")
	}
	return nil
}

func validateIPCPayloadLength(kind IPCFrameKind, length uint64) error {
	switch kind {
	case IPCFrameRequest:
		if length < minimumRequestPayload || length > maxIPCRequestPayload {
			return fmt.Errorf("approval IPC request payload length is outside %d..%d", minimumRequestPayload, maxIPCRequestPayload)
		}
	case IPCFrameSuccess:
		if length < minimumSuccessPayload || length > maxIPCSuccessPayload {
			return fmt.Errorf("approval IPC success payload length is outside %d..%d", minimumSuccessPayload, maxIPCSuccessPayload)
		}
	case IPCFrameError:
		if length != exactIPCErrorPayload {
			return fmt.Errorf("approval IPC error payload length must equal %d", exactIPCErrorPayload)
		}
	default:
		return fmt.Errorf("approval IPC frame kind is unknown")
	}
	return nil
}

func (code IPCErrorCode) valid() bool {
	return code >= IPCErrorUserCanceled && code <= IPCErrorInternalFailure
}

type p256ReceiptSignatureVerifier struct {
	publicKey *ecdsa.PublicKey
}

func (v p256ReceiptSignatureVerifier) Verify(ctx context.Context, keyGeneration, fingerprintSHA256 string, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyGeneration == "" || fingerprintSHA256 == "" {
		return fmt.Errorf("approval receipt key binding is empty")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(v.publicKey, digest[:], signature) {
		return fmt.Errorf("P-256 approval receipt signature does not verify")
	}
	return nil
}
