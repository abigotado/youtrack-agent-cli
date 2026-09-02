package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/application"
	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type migrationCredentials struct{ calls int }

func (*migrationCredentials) Exists(context.Context, string) (bool, error) { return true, nil }
func (*migrationCredentials) Load(context.Context, string) (auth.Credential, error) {
	return auth.Credential{}, auth.ErrNotFound
}
func (*migrationCredentials) Save(context.Context, string, auth.Credential) error { return nil }
func (*migrationCredentials) Delete(context.Context, string) error                { return nil }
func (store *migrationCredentials) MigrateKeychain(context.Context, string) error {
	store.calls++
	return nil
}

func testApp(t *testing.T) (*App, any, any, any, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	app := NewApp()
	app.stdin = bytes.NewReader(nil)
	app.stdout = stdout
	app.stderr = stderr
	return app, nil, nil, nil, stdout, stderr
}

func runApp(app *App, args ...string) errx.Code {
	return app.Run(context.Background(), app.NewRootCommand(), args)
}

func decode(t *testing.T, out *bytes.Buffer) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var envelope map[string]any
	if err := decoder.Decode(&envelope); err != nil {
		t.Fatalf("decode JSON envelope: %v\n%s", err, out.String())
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		t.Fatalf("stdout contains more than one JSON value: %s", out.String())
	}
	return envelope
}

func TestInspectRequiresExplicitProfile(t *testing.T) {
	app, _, _, _, stdout, stderr := testApp(t)
	code := runApp(app, "inspect", "issue", "--id", "APP-1", "-o", "json")
	if code != errx.CodeUsage {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if decode(t, stdout)["error"].(map[string]any)["code"] != "PROFILE_REQUIRED" {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestMutationApplyRejectsGlobalYesBeforeJournalAccess(t *testing.T) {
	app, _, _, _, stdout, stderr := testApp(t)
	code := runApp(app, "mutation", "apply", "--plan-id", "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA", "--yes", "-o", "json")
	if code != errx.CodeUsage {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if decode(t, stdout)["error"].(map[string]any)["code"] != "USAGE" {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestContractEmitsOneJSONEnvelope(t *testing.T) {
	app, _, _, _, stdout, stderr := testApp(t)
	code := runApp(app, "contract", "-o", "json")
	if code != errx.CodeOK || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if decode(t, stdout)["ok"] != true {
		t.Fatalf("stdout=%s", stdout.String())
	}
}

func TestKeychainMigrationRequiresConfirmationAndValidOutputFirst(t *testing.T) {
	registry := profile.NewRegistry(filepath.Join(t.TempDir(), "config", "profiles.json"))
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
		ExpectedAccountID: "1-2", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	if err := registry.Add(context.Background(), value); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		args     []string
		wantCode errx.Code
		wantCall int
	}{
		{"confirmation", []string{"auth", "migrate-keychain", "--profile", "work", "-o", "json"}, errx.CodeConfirm, 0},
		{"output validation", []string{"auth", "migrate-keychain", "--profile", "work", "--yes", "-o", "raw", "--fields", "profile"}, errx.CodeUsage, 0},
		{"confirmed", []string{"auth", "migrate-keychain", "--profile", "work", "--yes", "-o", "json"}, errx.CodeOK, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, _, _, _, stdout, stderr := testApp(t)
			credentials := &migrationCredentials{}
			app.service = &application.Service{Profiles: registry, Credentials: credentials}
			if code := runApp(app, test.args...); code != test.wantCode {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			if credentials.calls != test.wantCall {
				t.Fatalf("migration calls=%d want=%d", credentials.calls, test.wantCall)
			}
		})
	}
}
