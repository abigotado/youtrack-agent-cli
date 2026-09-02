// Package approval defines the trusted-user-presence boundary for guarded
// mutations. The first release intentionally supplies only a fail-closed
// adapter; receipt types and verification are ready for a separately signed
// native helper once Gate 1A is proven.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

const (
	// ReceiptSchemaVersion is the first durable approval receipt schema.
	ReceiptSchemaVersion = 1
	defaultMaximumTTL    = 5 * time.Minute
	defaultClockSkew     = 30 * time.Second
)

var (
	receiptIDPattern = regexp.MustCompile(`^YTAR-[A-Z2-7]{26}$`)
	noncePattern     = regexp.MustCompile(`^YTAN-[A-Z2-7]{26}$`)
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
	signature, err := base64.RawURLEncoding.DecodeString(receipt.Signature)
	if err != nil || len(signature) == 0 {
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
	type unsignedReceipt struct {
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
	}
	raw, err := json.Marshal(unsignedReceipt{
		SchemaVersion: receipt.SchemaVersion, ReceiptID: receipt.ReceiptID, Nonce: receipt.Nonce,
		PlanID: receipt.PlanID, PlanSHA256: receipt.PlanSHA256,
		ProfileIdentitySHA256: receipt.ProfileIdentitySHA256, AccountID: receipt.AccountID,
		ProjectID: receipt.ProjectID, ProjectKey: receipt.ProjectKey, SchemaSHA256: receipt.SchemaSHA256,
		RequestSHA256: receipt.RequestSHA256, ExpectedSHA256: receipt.ExpectedSHA256,
		IssuedAt: receipt.IssuedAt.UTC(), ExpiresAt: receipt.ExpiresAt.UTC(),
		KeyGeneration: receipt.KeyGeneration, KeyFingerprintSHA256: receipt.KeyFingerprintSHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal unsigned approval receipt: %w", err)
	}
	return raw, nil
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
	if receipt.SchemaVersion != ReceiptSchemaVersion || !receiptIDPattern.MatchString(receipt.ReceiptID) || !noncePattern.MatchString(receipt.Nonce) {
		return receiptError("RECEIPT_INVALID", "the approval receipt identifiers or schema are invalid")
	}
	if receipt.IssuedAt.IsZero() || receipt.ExpiresAt.IsZero() || !receipt.ExpiresAt.After(receipt.IssuedAt) {
		return receiptError("RECEIPT_TTL_INVALID", "the approval receipt time window is invalid")
	}
	for _, value := range []string{receipt.PlanSHA256, receipt.ProfileIdentitySHA256, receipt.SchemaSHA256, receipt.RequestSHA256, receipt.ExpectedSHA256, receipt.KeyFingerprintSHA256} {
		if !isSHA256(value) {
			return receiptError("RECEIPT_INVALID", "the approval receipt contains a non-canonical digest")
		}
	}
	if receipt.PlanID == "" || receipt.AccountID == "" || receipt.ProjectID == "" || receipt.ProjectKey == "" || strings.TrimSpace(receipt.KeyGeneration) == "" || receipt.Signature == "" {
		return receiptError("RECEIPT_INVALID", "the approval receipt is missing a required binding")
	}
	return nil
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
