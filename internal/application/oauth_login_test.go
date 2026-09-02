package application

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type oauthCredentialStore struct {
	value     auth.Credential
	exists    bool
	saveCalls int
}

func (s *oauthCredentialStore) Exists(context.Context, string) (bool, error) { return s.exists, nil }
func (s *oauthCredentialStore) Load(context.Context, string) (auth.Credential, error) {
	if !s.exists {
		return auth.Credential{}, auth.ErrNotFound
	}
	return s.value, nil
}
func (s *oauthCredentialStore) Save(_ context.Context, _ string, value auth.Credential) error {
	s.value = value
	s.exists = true
	s.saveCalls++
	return nil
}
func (s *oauthCredentialStore) Delete(context.Context, string) error {
	s.exists = false
	return nil
}
func (*oauthCredentialStore) MigrateKeychain(context.Context, string) error { return nil }

type callbackBrowser struct{}

func (callbackBrowser) Open(ctx context.Context, authorizationURL string) error {
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return err
	}
	callbackURL := parsed.Query().Get("redirect_uri") + "?code=authorization-code&state=" + url.QueryEscape(parsed.Query().Get("state"))
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, callbackURL, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.StatusCode != http.StatusOK {
		return errors.New("OAuth callback was rejected")
	}
	return nil
}

type oauthFlowTransport struct {
	scopeField string
	requests   int
}

func (transport *oauthFlowTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.requests++
	switch request.URL.Host {
	case "hub.example.test":
		body := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600` + transport.scopeField + `}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	case "tracker.example.test":
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"id":"1-42","login":"alice"}`)), Header: make(http.Header)}, nil
	default:
		return nil, errors.New("unexpected OAuth test origin")
	}
}

func oauthApplicationProfile(t *testing.T, authenticated bool) profile.Profile {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	serviceURL := "https://tracker.example.test"
	mcpURL, err := endpoint.CanonicalMCPURL(serviceURL)
	if err != nil {
		t.Fatal(err)
	}
	value := profile.Profile{
		Name: "work", ServiceURL: serviceURL, RESTBaseURL: serviceURL + endpoint.RESTPath, MCPURL: mcpURL,
		OAuth: profile.OAuthConfig{
			IssuerURL: "https://hub.example.test", AuthorizationURL: "https://hub.example.test" + endpoint.OAuthAuthorizationPath,
			TokenURL: "https://hub.example.test" + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"alpha", "beta"},
			RedirectURI: "http://" + address + "/oauth/callback",
		},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort,
	}
	if authenticated {
		value, err = value.WithNewCredentialGeneration()
		if err != nil {
			t.Fatal(err)
		}
	}
	return value
}

func oauthApplicationService(t *testing.T, selected profile.Profile, store *oauthCredentialStore, transport http.RoundTripper) *Service {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	if err := registry.Add(t.Context(), selected); err != nil {
		t.Fatal(err)
	}
	return &Service{Profiles: registry, Credentials: store, HTTP: transport}
}

func TestCallbackIgnoresInvalidRequestBeforeValidCallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	issuer := "https://hub.example.test"
	state := strings.Repeat("s", 43)
	config := oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://" + address + "/oauth/callback",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	callback, err := startCallback(ctx, config, state)
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Close(ctx)
	for _, query := range []string{"?code=bad&state=wrong", "?error=access_denied&state=wrong"} {
		response, getErr := http.Get(config.RedirectURI + query)
		if getErr != nil {
			t.Fatal(getErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid callback status=%d", response.StatusCode)
		}
	}
	response, err := http.Get(config.RedirectURI + "?code=good&state=" + state)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	code, err := callback.Wait(ctx)
	if err != nil || code != "good" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestLoginOAuthPersistsExactGrantedScopeSubset(t *testing.T) {
	selected := oauthApplicationProfile(t, false)
	store := &oauthCredentialStore{}
	transport := &oauthFlowTransport{scopeField: `,"scope":"beta"`}
	service := oauthApplicationService(t, selected, store, transport)

	loggedIn, err := service.LoginOAuth(t.Context(), selected.Name, false, callbackBrowser{})
	if err != nil {
		t.Fatal(err)
	}
	if store.saveCalls != 1 || !store.exists || !slices.Equal(store.value.OAuthScopes, []string{"beta"}) {
		t.Fatalf("stored credential scopes=%v saves=%d", store.value.OAuthScopes, store.saveCalls)
	}
	if loggedIn.CredentialGeneration == "" || auth.ValidateCredentialBinding(store.value, loggedIn) != nil {
		t.Fatalf("login binding is invalid: profile=%#v credential=%#v", loggedIn, store.value)
	}
}

func TestRefreshPersistsScopeWithoutReExpansion(t *testing.T) {
	for _, test := range []struct {
		name          string
		initialScopes []string
		wantScopes    []string
	}{
		{name: "modern subset", initialScopes: []string{"beta"}, wantScopes: []string{"beta"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected := oauthApplicationProfile(t, true)
			bound, err := auth.BindCredential(auth.Credential{
				Kind: auth.CredentialOAuth, AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer",
				AccessTokenExpiresAt: time.Unix(1_700_000_000, 0).UTC(), OAuthScopes: []string{"beta"},
			}, selected)
			if err != nil {
				t.Fatal(err)
			}
			bound.OAuthScopes = append([]string(nil), test.initialScopes...)
			store := &oauthCredentialStore{value: bound, exists: true}
			transport := &oauthFlowTransport{}
			service := oauthApplicationService(t, selected, store, transport)
			service.Now = func() time.Time { return time.Unix(1_700_000_100, 0).UTC() }

			status, err := service.AuthStatus(t.Context(), selected.Name, true)
			if err != nil || status.State != "valid" {
				t.Fatalf("status=%#v err=%v", status, err)
			}
			if store.saveCalls != 1 || !slices.Equal(store.value.OAuthScopes, test.wantScopes) {
				t.Fatalf("persisted scopes=%v saves=%d", store.value.OAuthScopes, store.saveCalls)
			}
		})
	}
}
