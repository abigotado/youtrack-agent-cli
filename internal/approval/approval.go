// Package approval defines the trusted-user-presence boundary for guarded
// mutations. The first release intentionally supplies only a fail-closed
// adapter; receipt types and verification are ready for a separately signed
// native helper once Gate 1A is proven.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

const (
	// ReceiptSchemaVersion is the first durable approval receipt schema.
	ReceiptSchemaVersion = 1
	// MaxApprovalDisplayBytes bounds the immutable canonical plan snapshot.
	MaxApprovalDisplayBytes = intent.MaxCanonicalPlanBytes
	// MaxReceiptBytes bounds one canonical signed receipt.
	MaxReceiptBytes = 4 << 10
	// MaxSigningBytes bounds the canonical unsigned receipt signed by the helper.
	MaxSigningBytes = 3 << 10
	// MaxKeyGenerationBytes bounds the non-secret helper-key generation label.
	MaxKeyGenerationBytes = 64
	// MaximumReceiptTTL is the longest receipt lifetime accepted by protocol v1.
	MaximumReceiptTTL = 5 * time.Minute

	defaultMaximumTTL = MaximumReceiptTTL
	defaultClockSkew  = 30 * time.Second
)

// Receipt is a non-secret, short-lived signed binding to one exact plan.
type Receipt struct {
	SchemaVersion         int       `json:"schema_version"`
	ReceiptID             string    `json:"receipt_id"`
	Nonce                 string    `json:"nonce"`
	PlanID                string    `json:"plan_id"`
	PlanSHA256            string    `json:"plan_sha256"`
	ProfileIdentitySHA256 string    `json:"profile_identity_sha256"`
	AccountID             string    `json:"account_id"`
	ProjectID             string    `json:"project_id"`
	ProjectKey            string    `json:"project_key"`
	SchemaSHA256          string    `json:"schema_sha256"`
	RequestSHA256         string    `json:"request_sha256"`
	ExpectedSHA256        string    `json:"expected_sha256"`
	IssuedAt              time.Time `json:"issued_at"`
	ExpiresAt             time.Time `json:"expires_at"`
	KeyGeneration         string    `json:"key_generation"`
	KeyFingerprintSHA256  string    `json:"key_fingerprint_sha256"`
	Signature             string    `json:"signature"`
}

// Approver displays one immutable canonical plan snapshot. A successful helper
// hashes those exact bytes into Receipt.PlanSHA256, constructs the remaining
// receipt fields, and signs the exact unsigned-receipt bytes from SigningBytes.
type Approver interface {
	Confirm(ctx context.Context, canonicalPlan []byte) (Receipt, error)
}

// Verifier verifies a receipt against the complete current plan binding.
type Verifier interface {
	Verify(ctx context.Context, plan intent.Plan, receipt Receipt) error
}

// SignatureVerifier is implemented by a code-identity-pinned native helper.
type SignatureVerifier interface {
	Verify(ctx context.Context, keyGeneration, fingerprintSHA256 string, message, signature []byte) error
}

// BindingVerifier validates receipt shape, binding, TTL, and signature.
type BindingVerifier struct {
	Signatures SignatureVerifier
	Now        func() time.Time
	MaximumTTL time.Duration
	ClockSkew  time.Duration
}

func (v BindingVerifier) Verify(ctx context.Context, plan intent.Plan, receipt Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return fmt.Errorf("verify receipt plan: %w", err)
	}
	displayed, err := intent.ApprovalDisplayBytes(plan)
	if err != nil {
		return fmt.Errorf("encode displayed approval plan: %w", err)
	}
	if err := ValidateApprovalDisplayBytes(displayed); err != nil {
		return err
	}
	displayedHash := sha256.Sum256(displayed)
	displayedSHA256 := hex.EncodeToString(displayedHash[:])
	if err := validateReceipt(receipt); err != nil {
		return err
	}
	if receipt.PlanID != plan.PlanID || receipt.PlanSHA256 != displayedSHA256 || receipt.PlanSHA256 != plan.IntentSHA256 ||
		receipt.ProfileIdentitySHA256 != plan.Profile.IdentitySHA256 ||
		receipt.AccountID != plan.Profile.Account.ID ||
		receipt.ProjectID != plan.Policy.Project.ID || receipt.ProjectKey != plan.Policy.Project.Key ||
		receipt.SchemaSHA256 != plan.Policy.SchemaSHA256 ||
		receipt.RequestSHA256 != plan.RequestSHA256 || receipt.ExpectedSHA256 != plan.ExpectedSHA256 {
		return receiptError("RECEIPT_BINDING_MISMATCH", "the approval receipt does not match the complete mutation plan")
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	maximumTTL := v.MaximumTTL
	if maximumTTL <= 0 {
		maximumTTL = defaultMaximumTTL
	}
	clockSkew := v.ClockSkew
	if clockSkew < 0 {
		return errx.Internal("approval verifier has a negative clock-skew allowance")
	}
	if clockSkew == 0 {
		clockSkew = defaultClockSkew
	}
	if receipt.ExpiresAt.Sub(receipt.IssuedAt) > maximumTTL {
		return receiptError("RECEIPT_TTL_INVALID", "the approval receipt lifetime exceeds the configured maximum")
	}
	if now.Before(receipt.IssuedAt.Add(-clockSkew)) {
		return receiptError("RECEIPT_NOT_YET_VALID", "the approval receipt was issued in the future")
	}
	if !now.Before(receipt.ExpiresAt) {
		return receiptError("RECEIPT_EXPIRED", "the approval receipt has expired")
	}
	if v.Signatures == nil {
		return userPresenceUnavailable()
	}
	message, err := SigningBytes(receipt)
	if err != nil {
		return err
	}
	signature, err := DecodeP256DERSignature(receipt.Signature)
	if err != nil {
		return receiptError("RECEIPT_SIGNATURE_INVALID", "the approval receipt signature is malformed")
	}
	if err := v.Signatures.Verify(ctx, receipt.KeyGeneration, receipt.KeyFingerprintSHA256, message, signature); err != nil {
		return receiptError("RECEIPT_SIGNATURE_INVALID", "the approval receipt signature is invalid").Wrap(err)
	}
	return nil
}

// SigningBytes returns the deterministic signature message. The helper first
// displays the canonical plan bytes, stores SHA256(displayed bytes) in
// PlanSHA256, then signs this unsigned-receipt encoding. Signature is excluded.
func SigningBytes(receipt Receipt) ([]byte, error) {
	if err := validateUnsignedReceipt(receipt); err != nil {
		return nil, err
	}
	issuedAt, err := canonicalReceiptTime(receipt.IssuedAt)
	if err != nil {
		return nil, err
	}
	expiresAt, err := canonicalReceiptTime(receipt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(unsignedReceiptWire{
		SchemaVersion: receipt.SchemaVersion, ReceiptID: receipt.ReceiptID, Nonce: receipt.Nonce,
		PlanID: receipt.PlanID, PlanSHA256: receipt.PlanSHA256,
		ProfileIdentitySHA256: receipt.ProfileIdentitySHA256, AccountID: receipt.AccountID,
		ProjectID: receipt.ProjectID, ProjectKey: receipt.ProjectKey, SchemaSHA256: receipt.SchemaSHA256,
		RequestSHA256: receipt.RequestSHA256, ExpectedSHA256: receipt.ExpectedSHA256,
		IssuedAt: issuedAt, ExpiresAt: expiresAt,
		KeyGeneration: receipt.KeyGeneration, KeyFingerprintSHA256: receipt.KeyFingerprintSHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal unsigned approval receipt: %w", err)
	}
	if len(raw) > MaxSigningBytes {
		return nil, receiptError("RECEIPT_INVALID", "the approval signing message exceeds the protocol limit")
	}
	return raw, nil
}

// ValidateApprovalDisplayBytes applies the v1 byte bound before a native
// helper copies, decodes, or renders an immutable approval snapshot.
func ValidateApprovalDisplayBytes(canonicalPlan []byte) error {
	if len(canonicalPlan) == 0 || len(canonicalPlan) > MaxApprovalDisplayBytes {
		return receiptError("APPROVAL_DISPLAY_INVALID", "the approval display snapshot is empty or exceeds the protocol limit")
	}
	return nil
}

// Unsupported is the mandatory adapter until Gate 1A proves a trusted helper.
// It has no terminal, environment, stdin, or command-line confirmation path.
type Unsupported struct{}

func (Unsupported) Confirm(ctx context.Context, canonicalPlan []byte) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	return Receipt{}, userPresenceUnavailable()
}

func (Unsupported) Verify(ctx context.Context, plan intent.Plan, receipt Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return userPresenceUnavailable()
}

func validateReceipt(receipt Receipt) error {
	if err := validateUnsignedReceipt(receipt); err != nil {
		return err
	}
	if _, err := DecodeP256DERSignature(receipt.Signature); err != nil {
		return receiptError("RECEIPT_SIGNATURE_INVALID", "the approval receipt signature is malformed")
	}
	return nil
}

func validateUnsignedReceipt(receipt Receipt) error {
	if receipt.SchemaVersion != ReceiptSchemaVersion || validateCanonicalApprovalID(receipt.ReceiptID, receiptIDPrefix) != nil || validateCanonicalApprovalID(receipt.Nonce, noncePrefix) != nil {
		return receiptError("RECEIPT_INVALID", "the approval receipt identifiers or schema are invalid")
	}
	if intent.ValidatePlanID(receipt.PlanID) != nil || !isCanonicalIdentifier(receipt.AccountID) || !isCanonicalIdentifier(receipt.ProjectID) || !isCanonicalProjectKey(receipt.ProjectKey) {
		return receiptError("RECEIPT_INVALID", "the approval receipt contains a non-canonical plan, account, or project binding")
	}
	if _, err := canonicalReceiptTime(receipt.IssuedAt); err != nil {
		return err
	}
	if _, err := canonicalReceiptTime(receipt.ExpiresAt); err != nil {
		return err
	}
	if !receipt.ExpiresAt.After(receipt.IssuedAt) || receipt.ExpiresAt.Sub(receipt.IssuedAt) > MaximumReceiptTTL {
		return receiptError("RECEIPT_TTL_INVALID", "the approval receipt time window is invalid")
	}
	for _, value := range []string{receipt.PlanSHA256, receipt.ProfileIdentitySHA256, receipt.SchemaSHA256, receipt.RequestSHA256, receipt.ExpectedSHA256, receipt.KeyFingerprintSHA256} {
		if !isSHA256(value) {
			return receiptError("RECEIPT_INVALID", "the approval receipt contains a non-canonical digest")
		}
	}
	if !isCanonicalKeyGeneration(receipt.KeyGeneration) {
		return receiptError("RECEIPT_INVALID", "the approval receipt key generation is not canonical")
	}
	return nil
}

func canonicalReceiptTime(value time.Time) (string, error) {
	if value.IsZero() || value.Year() < 1 || value.Year() > 9999 || value.Nanosecond() != 0 {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use whole seconds")
	}
	_, offset := value.Zone()
	if offset != 0 {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use UTC")
	}
	encoded := value.UTC().Format(time.RFC3339)
	if len(encoded) != len("2006-01-02T15:04:05Z") {
		return "", receiptError("RECEIPT_TTL_INVALID", "approval receipt times must use four-digit RFC3339 years")
	}
	return encoded, nil
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == sha256.Size
}

func receiptError(reason, message string) *errx.Error {
	return &errx.Error{Code: errx.CodeConfirm, Reason: reason, Message: message, Hint: "discard the receipt and obtain a fresh trusted approval"}
}

func userPresenceUnavailable() *errx.Error {
	return &errx.Error{
		Code: errx.CodeConfirm, Reason: "USER_PRESENCE_UNAVAILABLE",
		Message: "trusted user-presence approval is unavailable because Gate 1A has not passed",
		Hint:    "do not apply the mutation; use prepare/status only until the signed native helper is approved",
	}
}
