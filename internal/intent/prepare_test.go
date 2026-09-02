package intent

import (
	"bytes"
	"errors"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type fixedIDSource string

func (s fixedIDSource) NewPlanID() (string, error) { return string(s), nil }

func validBindings() (ProfileSnapshot, ProjectPolicy) {
	return ProfileSnapshot{
		Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test",
		IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "generation-1",
		Account: AccountBinding{ID: "1-2", Login: "alice"},
	}, ProjectPolicy{
		Project: ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 2,
		PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64),
		ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-create",
		NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker",
	}
}

func TestPrepareDeterministicAndMarkerBound(t *testing.T) {
	profile, policy := validBindings()
	requestA := []byte(`{"summary":"Created","description":"body","visibility":{"mode":"public"},"custom_fields":[{"field_id":"2-2","field_type":"enum","value_id":"3-2"},{"field_id":"2-1","field_type":"enum","value_id":"3-1"}],"marker":"visible_footer"}`)
	requestB := []byte(`{"summary":"Created","description":"body","visibility":{"mode":"public"},"custom_fields":[{"field_id":"2-1","field_type":"enum","value_id":"3-1"},{"field_id":"2-2","field_type":"enum","value_id":"3-2"}],"marker":"visible_footer"}`)
	expected := []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")

	first, err := PrepareWithSource(profile, policy, KindIssueCreate, requestA, expected, source)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareWithSource(profile, policy, KindIssueCreate, requestB, expected, source)
	if err != nil {
		t.Fatal(err)
	}
	if first.IntentSHA256 != second.IntentSHA256 || first.RequestSHA256 != second.RequestSHA256 {
		t.Fatalf("canonical hashes differ: %#v %#v", first, second)
	}
	if got := first.Operation.IssueCreate.Request.Description; got != "body\n\nAgent plan: "+first.PlanID {
		t.Fatalf("description = %q", got)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("prepared plan invalid: %v", err)
	}
}

func TestPrepareStrictBoundsAndKinds(t *testing.T) {
	profile, policy := validBindings()
	source := fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA")
	tests := []struct {
		name     string
		kind     Kind
		request  []byte
		expected []byte
		wantErr  error
	}{
		{"create", KindIssueCreate, []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`), []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), nil},
		{"update", KindIssueUpdate, []byte(`{"issue_id":"APP-1","set":{"summary":"S"}}`), []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`), nil},
		{"comment", KindCommentAdd, []byte(`{"issue_id":"APP-1","text":"hello","visibility":{"mode":"restricted","group_ids":["1-1"]},"marker":"none"}`), []byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), nil},
		{"unknown field", KindIssueCreate, []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none","extra":true}`), []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`), ErrInvalidPlan},
		{"oversized", KindIssueCreate, []byte(strings.Repeat("x", MaxRequestBytes+1)), []byte(`{}`), ErrInputTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy.AuthorizedCapability = authorizedCapability(tt.kind)
			_, err := PrepareWithSource(profile, policy, tt.kind, tt.request, tt.expected, source)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestPlanTamperInvalidatesDigest(t *testing.T) {
	profile, policy := validBindings()
	policy.AuthorizedCapability = "issue-update"
	plan, err := PrepareWithSource(profile, policy, KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"S"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := plan
	changed := "changed"
	tampered.Operation.IssueUpdate.Request.Set.Summary = &changed
	if !errors.Is(tampered.Validate(), ErrInvalidPlan) {
		t.Fatalf("tampered plan validated")
	}
}

func TestApprovalDisplayBytesContainEverySafetyBinding(t *testing.T) {
	profile, policy := validBindings()
	plan, err := PrepareWithSource(profile, policy, KindIssueCreate,
		[]byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`),
		[]byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`),
		fixedIDSource("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatal(err)
	}
	displayed, err := ApprovalDisplayBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(displayed, canonical) {
		t.Fatal("approval bytes differ from signed canonical bytes")
	}
	for _, binding := range []string{
		`"rest_base_url":"https://acme.youtrack.cloud/api"`,
		`"oauth_issuer_url":"https://hub.example.test"`,
		`"account":{"id":"1-2","login":"alice"}`,
		`"authorized_capability":"issue-create"`,
		`"notification_policy":"youtrack-default"`,
		`"reconciliation_strategy":"bounded-exact-and-marker"`,
		`"executor_assurance":"rest-best-effort"`,
	} {
		if !bytes.Contains(displayed, []byte(binding)) {
			t.Fatalf("approval bytes missing %s: %s", binding, displayed)
		}
	}
}

func TestPreparePackageHasNoOnlineOrCredentialImports(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	packages, err := parser.ParseDir(token.NewFileSet(), filepath.Dir(filename), nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range packages["intent"].Files {
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path == "net/http" || path == "os/exec" || strings.Contains(path, "/internal/auth") {
				t.Fatalf("offline intent package imports forbidden dependency %q", path)
			}
		}
	}
}
