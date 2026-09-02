package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

type fixedID string

func (f fixedID) NewPlanID() (string, error) { return string(f), nil }

type digestVerifier struct{}

func (digestVerifier) Verify(ctx context.Context, keyGeneration, fingerprint string, message, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	sum := sha256.Sum256(message)
	if !bytes.Equal(sum[:], signature) {
		return errors.New("signature mismatch")
	}
	return nil
}

func approvalPlan(t *testing.T) intent.Plan {
	t.Helper()
	plan, err := intent.PrepareWithSource(
		intent.ProfileSnapshot{Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test", IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "gen-1", Account: intent.AccountBinding{ID: "1-2", Login: "alice"}},
		intent.ProjectPolicy{Project: intent.ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 1, PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64), ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "comment-add", NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker"},
		intent.KindCommentAdd,
		[]byte(`{"issue_id":"APP-1","text":"hello","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func signedReceipt(t *testing.T, plan intent.Plan, issued time.Time) Receipt {
	t.Helper()
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB", PlanID: plan.PlanID,
		PlanSHA256: plan.IntentSHA256, ProfileIdentitySHA256: plan.Profile.IdentitySHA256,
		AccountID: plan.Profile.Account.ID, ProjectID: plan.Policy.Project.ID,
		ProjectKey: plan.Policy.Project.Key, SchemaSHA256: plan.Policy.SchemaSHA256,
		RequestSHA256: plan.RequestSHA256, ExpectedSHA256: plan.ExpectedSHA256,
		IssuedAt: issued, ExpiresAt: issued.Add(5 * time.Minute),
		KeyGeneration: "key-1", KeyFingerprintSHA256: strings.Repeat("e", 64),
	}
	message, err := SigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(message)
	receipt.Signature = base64.RawURLEncoding.EncodeToString(sum[:])
	return receipt
}

func TestBindingVerifierTamperTTLAndSignature(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	plan := approvalPlan(t)
	valid := signedReceipt(t, plan, now.Add(-time.Minute))
	tests := []struct {
		name    string
		mutate  func(*Receipt)
		wantErr bool
	}{
		{"valid", func(*Receipt) {}, false},
		{"binding tamper", func(r *Receipt) { r.ProjectKey = "OTHER" }, true},
		{"expired", func(r *Receipt) { r.IssuedAt = now.Add(-10 * time.Minute); r.ExpiresAt = now.Add(-5 * time.Minute) }, true},
		{"ttl too long", func(r *Receipt) { r.ExpiresAt = r.IssuedAt.Add(6 * time.Minute) }, true},
		{"signature tamper", func(r *Receipt) { r.Signature = base64.RawURLEncoding.EncodeToString([]byte("wrong")) }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receipt := valid
			tt.mutate(&receipt)
			err := (BindingVerifier{Signatures: digestVerifier{}, Now: func() time.Time { return now }}).Verify(context.Background(), plan, receipt)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSigningBytesGoldenVector(t *testing.T) {
	receipt := Receipt{
		SchemaVersion: 1, ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB",
		PlanID: "YTAP-CCCCCCCCCCCCCCCCCCCCCCCCCC", PlanSHA256: strings.Repeat("1", 64),
		ProfileIdentitySHA256: strings.Repeat("2", 64), AccountID: "1-2", ProjectID: "0-1", ProjectKey: "APP",
		SchemaSHA256: strings.Repeat("3", 64), RequestSHA256: strings.Repeat("4", 64), ExpectedSHA256: strings.Repeat("5", 64),
		IssuedAt:      time.Date(2026, 9, 2, 12, 34, 56, 0, time.FixedZone("offset", -3*60*60)),
		ExpiresAt:     time.Date(2026, 9, 2, 12, 39, 56, 0, time.FixedZone("offset", -3*60*60)),
		KeyGeneration: "key-1", KeyFingerprintSHA256: strings.Repeat("6", 64), Signature: "excluded",
	}
	got, err := SigningBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":1,"receipt_id":"YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA","nonce":"YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB","plan_id":"YTAP-CCCCCCCCCCCCCCCCCCCCCCCCCC","plan_sha256":"1111111111111111111111111111111111111111111111111111111111111111","profile_identity_sha256":"2222222222222222222222222222222222222222222222222222222222222222","account_id":"1-2","project_id":"0-1","project_key":"APP","schema_sha256":"3333333333333333333333333333333333333333333333333333333333333333","request_sha256":"4444444444444444444444444444444444444444444444444444444444444444","expected_sha256":"5555555555555555555555555555555555555555555555555555555555555555","issued_at":"2026-09-02T15:34:56Z","expires_at":"2026-09-02T15:39:56Z","key_generation":"key-1","key_fingerprint_sha256":"6666666666666666666666666666666666666666666666666666666666666666"}`
	if string(got) != want {
		t.Fatalf("signing bytes changed\n got: %s\nwant: %s", got, want)
	}
}

func TestUnsupportedAlwaysFailsClosed(t *testing.T) {
	plan := approvalPlan(t)
	_, err := (Unsupported{}).Confirm(context.Background(), []byte("immutable"))
	assertPresenceUnavailable(t, err)
	assertPresenceUnavailable(t, (Unsupported{}).Verify(context.Background(), plan, Receipt{}))
}

func assertPresenceUnavailable(t *testing.T, err error) {
	t.Helper()
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "USER_PRESENCE_UNAVAILABLE" || typed.Code != errx.CodeConfirm {
		t.Fatalf("error = %#v", err)
	}
}
