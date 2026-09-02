package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return fn(request) }

func testConfig() Config {
	issuer := "https://hub.example.test"
	return Config{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath, TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"}
}

func TestPKCEAndCallback(t *testing.T) {
	session, err := NewSession(strings.NewReader(strings.Repeat("a", 64)))
	if err != nil || session.State == "" || session.Verifier == "" || session.Challenge == session.Verifier {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	authURL, err := AuthorizationURL(testConfig(), session)
	if err != nil || !strings.Contains(authURL, "code_challenge_method=S256") {
		t.Fatalf("URL=%q err=%v", authURL, err)
	}
	code, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?code=code-value&state="+session.State, session.State)
	if err != nil || code != "code-value" {
		t.Fatalf("code=%q err=%v", code, err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?code=x&state=wrong", session.State); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("state error=%v", err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?error=access_denied&state=wrong", session.State); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("denial with wrong state error=%v", err)
	}
	if _, err := ParseCallback(testConfig(), testConfig().RedirectURI+"?error=access_denied&state="+session.State, session.State); !errors.Is(err, ErrAuthorizationDenied) {
		t.Fatalf("denial with valid state error=%v", err)
	}
}

func TestExchangeAndRefreshRotation(t *testing.T) {
	var bodies []string
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(raw))
		response := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600,"scope":"YouTrack"}`
		if len(bodies) == 2 {
			response = `{"access_token":"next","refresh_token":"rotated","token_type":"bearer","expires_in":3600}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
	})
	client, err := NewClient(testConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(100, 0) }
	session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := client.Exchange(t.Context(), "code", session.Verifier)
	if err != nil || tokens.RefreshToken != "refresh" {
		t.Fatalf("tokens=%#v err=%v", tokens, err)
	}
	tokens, err = client.Refresh(t.Context(), tokens)
	if err != nil || tokens.RefreshToken != "rotated" || !strings.Contains(bodies[1], "grant_type=refresh_token") {
		t.Fatalf("tokens=%#v err=%v bodies=%v", tokens, err, bodies)
	}
}

func TestExchangeTreatsGrantedScopesAsStrictSubset(t *testing.T) {
	config := testConfig()
	config.Scopes = []string{"alpha", "beta", "gamma"}
	tests := []struct {
		name       string
		scopeField string
		want       []string
		wantErr    bool
	}{
		{name: "reordered subset", scopeField: `,"scope":"gamma alpha"`, want: []string{"alpha", "gamma"}},
		{name: "single subset", scopeField: `,"scope":"beta"`, want: []string{"beta"}},
		{name: "omitted means requested", want: []string{"alpha", "beta", "gamma"}},
		{name: "present empty is malformed", scopeField: `,"scope":""`, wantErr: true},
		{name: "present null is malformed", scopeField: `,"scope":null`, wantErr: true},
		{name: "double separator is malformed", scopeField: `,"scope":"alpha  beta"`, wantErr: true},
		{name: "tab separator is malformed", scopeField: `,"scope":"alpha\tbeta"`, wantErr: true},
		{name: "newline separator is malformed", scopeField: `,"scope":"alpha\nbeta"`, wantErr: true},
		{name: "leading separator is malformed", scopeField: `,"scope":" alpha"`, wantErr: true},
		{name: "duplicate is malformed", scopeField: `,"scope":"alpha alpha"`, wantErr: true},
		{name: "escalated scope", scopeField: `,"scope":"admin"`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session, err := NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
				body := `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":3600` + test.scopeField + `}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			client, err := NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			tokens, err := client.Exchange(t.Context(), "code", session.Verifier)
			if test.wantErr {
				if !errors.Is(err, ErrTokenExchange) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || !slices.Equal(tokens.Scopes, test.want) {
				t.Fatalf("scopes=%v err=%v", tokens.Scopes, err)
			}
		})
	}
}

func TestRefreshPreservesOrNarrowsCurrentGrant(t *testing.T) {
	config := testConfig()
	config.Scopes = []string{"alpha", "beta", "gamma"}
	tests := []struct {
		name       string
		scopeField string
		want       []string
		wantErr    bool
	}{
		{name: "omitted scope preserves current grant", want: []string{"alpha", "gamma"}},
		{name: "explicit narrowing", scopeField: `,"scope":"gamma"`, want: []string{"gamma"}},
		{name: "cannot re-expand from current grant", scopeField: `,"scope":"alpha beta gamma"`, wantErr: true},
		{name: "present empty is malformed", scopeField: `,"scope":""`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(request.Body)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(raw), "grant_type=refresh_token") {
					t.Fatalf("refresh form = %q", raw)
				}
				body := `{"access_token":"next","token_type":"Bearer","expires_in":3600` + test.scopeField + `}`
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})
			client, err := NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			current := TokenSet{AccessToken: "old", RefreshToken: "refresh", TokenType: "Bearer", Scopes: []string{"alpha", "gamma"}}
			tokens, err := client.Refresh(t.Context(), current)
			if test.wantErr {
				if !errors.Is(err, ErrTokenExchange) {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err != nil || tokens.RefreshToken != current.RefreshToken || !slices.Equal(tokens.Scopes, test.want) {
				t.Fatalf("tokens=%#v err=%v", tokens, err)
			}
		})
	}
}

func TestTokenResponseIsBoundedAndErrorsAreRedacted(t *testing.T) {
	sentinel := "server-secret-sentinel"
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader(sentinel)), Header: make(http.Header)}, nil
	})
	client, err := NewClient(testConfig(), transport)
	if err != nil {
		t.Fatal(err)
	}
	session, sessionErr := NewSession(strings.NewReader(strings.Repeat("v", 64)))
	if sessionErr != nil {
		t.Fatal(sessionErr)
	}
	_, err = client.Exchange(t.Context(), "code", session.Verifier)
	if !errors.Is(err, ErrTokenExchange) || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error=%v", err)
	}
}

func TestTokenSetCannotEnterFormattingOrJSON(t *testing.T) {
	tokens := TokenSet{AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel"}
	if formatted := fmt.Sprintf("%v", tokens); strings.Contains(formatted, "sentinel") {
		t.Fatalf("format exposed token: %q", formatted)
	}
	raw, err := json.Marshal(tokens)
	if err != nil || strings.Contains(string(raw), "sentinel") {
		t.Fatalf("JSON exposed token: %s, %v", raw, err)
	}
}
