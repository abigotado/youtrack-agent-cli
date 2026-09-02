package application

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/approval"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/journal"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
)

type trapCredentials struct{ calls int }

func (store *trapCredentials) Exists(context.Context, string) (bool, error) {
	store.calls++
	return false, errors.New("credential trap called")
}
func (store *trapCredentials) Load(context.Context, string) (auth.Credential, error) {
	store.calls++
	return auth.Credential{}, errors.New("credential trap called")
}
func (store *trapCredentials) Save(context.Context, string, auth.Credential) error {
	store.calls++
	return errors.New("credential trap called")
}
func (store *trapCredentials) Delete(context.Context, string) error {
	store.calls++
	return errors.New("credential trap called")
}
func (store *trapCredentials) MigrateKeychain(context.Context, string) error {
	store.calls++
	return errors.New("credential trap called")
}

type trapTransport struct{ calls int }

func (transport *trapTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls++
	return nil, errors.New("network trap called")
}

type existingCredentials struct{ emptyCredentials }

func (*existingCredentials) Exists(context.Context, string) (bool, error) { return true, nil }

type trapBrowser struct{ calls int }

func (browser *trapBrowser) Open(context.Context, string) error {
	browser.calls++
	return errors.New("browser trap called")
}

type countingReader struct{ calls int }

func (reader *countingReader) Read([]byte) (int, error) {
	reader.calls++
	return 0, io.EOF
}

func mutationService(t *testing.T) (*Service, *trapCredentials, *trapTransport) {
	t.Helper()
	directory := t.TempDir()
	configDirectory := filepath.Join(directory, "config")
	profiles := profile.NewRegistry(filepath.Join(configDirectory, "profiles.json"))
	policies := writepolicy.NewRegistry(filepath.Join(configDirectory, "write-policies.json"))
	serviceURL := "https://tracker.example.test"
	mcpURL, err := endpoint.CanonicalMCPURL(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	value := profile.Profile{
		Name: "work", ServiceURL: serviceURL, RESTBaseURL: serviceURL + endpoint.RESTPath, MCPURL: mcpURL,
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath,
			TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
			RedirectURI: "http://127.0.0.1:18987/oauth/callback",
		},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice",
		Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate},
		Executor:     profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	value, err = value.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	if err := profiles.Add(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	if _, err := policies.Set(context.Background(), value, []writepolicy.Project{{ID: "0-1", Key: "APP"}}); err != nil {
		t.Fatal(err)
	}
	credentials := &trapCredentials{}
	transport := &trapTransport{}
	return &Service{
		Profiles: profiles, Policies: policies, Credentials: credentials,
		Journal: journal.New(filepath.Join(directory, "journal")), Approver: approval.Unsupported{}, HTTP: transport,
	}, credentials, transport
}

func validPrepareInput(outputPath string) MutationPrepareInput {
	return MutationPrepareInput{
		Profile: "work", Kind: "issue.update", Project: ProjectRef{ID: "0-1", Key: "APP"},
		SchemaSHA256: strings.Repeat("a", 64), OutputPath: outputPath,
		RequestJSON:  []byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		ExpectedJSON: []byte(`{"issue_id":"APP-1","issue_state_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","touched_fields_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}`),
	}
}

func TestPrepareMutationIsOfflineAndExportsExclusivePlan(t *testing.T) {
	service, credentials, transport := mutationService(t)
	path := filepath.Join(t.TempDir(), "plan.json")
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(path))
	if err != nil {
		t.Fatal(err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("offline prepare touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
	if result.State != "prepared" || result.PlanID == "" || result.OutputPath != path {
		t.Fatalf("mutation result=%+v", result)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("plan mode=%v", info.Mode().Perm())
	}
}

func TestPrepareExportFailureKeepsAuthoritativeJournalRecord(t *testing.T) {
	service, _, _ := mutationService(t)
	directory := t.TempDir()
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(directory))
	if err == nil || result.PlanID == "" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	recorded, statusErr := service.MutationStatusInfo(context.Background(), result.PlanID)
	if statusErr != nil || recorded.State != "prepared" {
		t.Fatalf("recorded=%+v err=%v", recorded, statusErr)
	}
}

func TestPrepareMutationRequiresExactOperationCapability(t *testing.T) {
	service, credentials, transport := mutationService(t)
	input := validPrepareInput("")
	input.Kind = "issue.create"
	input.RequestJSON = []byte(`{"summary":"S","description":"","visibility":{"mode":"public"},"marker":"none"}`)
	input.ExpectedJSON = []byte(`{"project_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}`)
	_, err := service.PrepareMutationInfo(context.Background(), input)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "MUTATION_CAPABILITY_REQUIRED" {
		t.Fatalf("error=%v", err)
	}
	if credentials.calls != 0 || transport.calls != 0 {
		t.Fatalf("capability rejection touched credentials=%d network=%d", credentials.calls, transport.calls)
	}
}

func TestPrepareExportFailurePreservesPlanIDAndCanReexport(t *testing.T) {
	service, _, _ := mutationService(t)
	directory := t.TempDir()
	blocked := filepath.Join(directory, "already-exists.json")
	if err := os.WriteFile(blocked, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	record, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(blocked))
	if err == nil || record.PlanID == "" || !strings.Contains(err.Error(), record.PlanID) {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Code != errx.CodeUsage || typed.Reason != "PLAN_EXPORT_FAILED" ||
		!strings.Contains(typed.Hint, "mutation export --plan-id "+record.PlanID) {
		t.Fatalf("export error contract=%#v", err)
	}
	if status, statusErr := service.MutationStatusInfo(context.Background(), record.PlanID); statusErr != nil || status.State != "prepared" {
		t.Fatalf("status=%#v err=%v", status, statusErr)
	}
	reexport := filepath.Join(directory, "reexport.json")
	exported, exportErr := service.ExportMutationInfo(context.Background(), record.PlanID, reexport)
	if exportErr != nil || exported.OutputPath != reexport {
		t.Fatalf("exported=%#v err=%v", exported, exportErr)
	}
	if info, statErr := os.Stat(reexport); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("reexport info=%v err=%v", info, statErr)
	}
}

func TestConfirmAndApplyFailClosedWithoutChangingPreparedState(t *testing.T) {
	service, _, _ := mutationService(t)
	result, err := service.PrepareMutationInfo(context.Background(), validPrepareInput(""))
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		run  func() error
	}{
		{name: "confirm", run: func() error { return service.ConfirmMutation(context.Background(), result.PlanID) }},
		{name: "apply", run: func() error { return service.ApplyMutation(context.Background(), "work", result.PlanID) }},
	} {
		t.Run(operation.name, func(t *testing.T) {
			err := operation.run()
			var typed *errx.Error
			if !errors.As(err, &typed) || typed.Reason != "USER_PRESENCE_UNAVAILABLE" {
				t.Fatalf("error=%v", err)
			}
			current, statusErr := service.MutationStatusInfo(context.Background(), result.PlanID)
			if statusErr != nil || current.State != "prepared" || current.Revision != 1 {
				t.Fatalf("current=%+v err=%v", current, statusErr)
			}
		})
	}
}

func TestSaveProfileRefusesToOrphanBoundCredential(t *testing.T) {
	service, _, _ := mutationService(t)
	existing, err := service.GetProfile(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	loginIntent, err := existing.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	service.Credentials = &emptyCredentials{}
	_, err = service.SaveProfile(context.Background(), loginIntent, true)
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "PROFILE_AUTHENTICATED" {
		t.Fatalf("error=%v", err)
	}
	current, err := service.GetProfile(context.Background(), "work")
	if err != nil || current.CredentialGeneration != existing.CredentialGeneration {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestCredentialReplacementConfirmationPrecedesOAuthSideEffects(t *testing.T) {
	service, _, transport := mutationService(t)
	service.Credentials = &existingCredentials{}
	browser := &trapBrowser{}
	_, err := service.LoginOAuth(context.Background(), "work", false, browser)
	if !errors.Is(err, auth.ErrOverwriteConfirmationRequired) {
		t.Fatalf("error=%v", err)
	}
	if browser.calls != 0 || transport.calls != 0 {
		t.Fatalf("preflight touched browser=%d network=%d", browser.calls, transport.calls)
	}
}

func TestCredentialReplacementConfirmationPrecedesTokenRead(t *testing.T) {
	service, _, transport := mutationService(t)
	service.Credentials = &existingCredentials{}
	reader := &countingReader{}
	_, err := service.ImportPermanentTokenReader(context.Background(), "work", reader, false)
	if !errors.Is(err, auth.ErrOverwriteConfirmationRequired) {
		t.Fatalf("error=%v", err)
	}
	if reader.calls != 0 || transport.calls != 0 {
		t.Fatalf("preflight touched reader=%d network=%d", reader.calls, transport.calls)
	}
}

type emptyCredentials struct{}

func (*emptyCredentials) Exists(context.Context, string) (bool, error) { return false, nil }
func (*emptyCredentials) Load(context.Context, string) (auth.Credential, error) {
	return auth.Credential{}, auth.ErrNotFound
}
func (*emptyCredentials) Save(context.Context, string, auth.Credential) error { return nil }
func (*emptyCredentials) Delete(context.Context, string) error                { return nil }
func (*emptyCredentials) MigrateKeychain(context.Context, string) error       { return nil }
