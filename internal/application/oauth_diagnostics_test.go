package application

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/output"
)

type oauthDiagnosticTransport func(*http.Request) (*http.Response, error)

func (transport oauthDiagnosticTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func TestOAuthTokenDiagnosticsKeepV1EnvelopeAndRecoveryExit(t *testing.T) {
	const sentinel = "server-secret-sentinel"
	tests := []struct {
		name      string
		status    int
		body      string
		location  string
		transport error
		code      string
		exit      errx.Code
	}{
		{name: "transport", transport: errors.New("transport-secret-sentinel"), code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "TLS trust failure", transport: x509.UnknownAuthorityError{}, code: "OAUTH_TOKEN_TRANSPORT_REJECTED", exit: errx.CodeAuth},
		{name: "retryable", status: http.StatusServiceUnavailable, body: sentinel, code: "OAUTH_TOKEN_ENDPOINT_UNAVAILABLE", exit: errx.CodeRetryable},
		{name: "rejected", status: http.StatusBadRequest, body: sentinel, code: "OAUTH_TOKEN_REQUEST_REJECTED", exit: errx.CodeAuth},
		{name: "invalid response", status: http.StatusOK, body: `{"access_token":"` + sentinel + `"`, code: "OAUTH_TOKEN_RESPONSE_INVALID", exit: errx.CodeAuth},
		{name: "redirect refused", status: http.StatusFound, body: sentinel, location: "https://other.example.test/secret-sentinel", code: "OAUTH_TOKEN_REDIRECT_REFUSED", exit: errx.CodeAuth},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer := "https://hub.example.test"
			config := oauth.Config{
				IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
				TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
				RedirectURI: "http://127.0.0.1:18987/oauth/callback",
			}
			calls := 0
			transport := oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
				calls++
				if test.transport != nil {
					return nil, test.transport
				}
				header := make(http.Header)
				header.Set("X-Secret", sentinel)
				if test.location != "" {
					header.Set("Location", test.location)
				}
				return &http.Response{StatusCode: test.status, Body: io.NopCloser(strings.NewReader(test.body)), Header: header}, nil
			})
			client, err := oauth.NewClient(config, transport)
			if err != nil {
				t.Fatal(err)
			}
			session, err := oauth.NewSession(strings.NewReader(strings.Repeat("v", 64)))
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Exchange(t.Context(), "authorization-code-secret-sentinel", session.Verifier)
			if !errors.Is(err, oauth.ErrTokenExchange) {
				t.Fatalf("OAuth error=%v", err)
			}
			translated := TranslateError(err, "work")
			if errx.ExitCode(translated) != test.exit {
				t.Fatalf("exit=%d, want %d", errx.ExitCode(translated), test.exit)
			}
			var stdout, stderr bytes.Buffer
			writer := &output.Writer{Format: output.FormatJSON, Out: &stdout, Err: &stderr}
			if exit := writer.Failure(translated); exit != test.exit {
				t.Fatalf("rendered exit=%d, want %d", exit, test.exit)
			}
			if calls != 1 || stderr.Len() != 0 || !bytes.HasSuffix(stdout.Bytes(), []byte("\n")) {
				t.Fatalf("requests=%d stderr=%q stdout=%q", calls, stderr.String(), stdout.String())
			}
			var envelope output.Envelope
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.OK || envelope.V != 1 || envelope.Error == nil || envelope.Error.Code != test.code || envelope.Error.Message == "" || envelope.Hint == "" {
				t.Fatalf("envelope=%+v", envelope)
			}
			if test.status != 0 && !strings.Contains(envelope.Error.Message, fmt.Sprintf("HTTP %d", test.status)) {
				t.Fatalf("status missing from safe message: %q", envelope.Error.Message)
			}
			if test.status == 0 && strings.Contains(envelope.Error.Message, "HTTP 0") {
				t.Fatalf("transport failure invented HTTP status: %q", envelope.Error.Message)
			}
			if strings.Contains(stdout.String(), "secret-sentinel") || strings.Contains(stdout.String(), "other.example.test") {
				t.Fatalf("v1 envelope leaked untrusted OAuth content: %q", stdout.String())
			}
		})
	}
}

func TestUntypedOAuthFailureRetainsPublishedRecovery(t *testing.T) {
	translated := TranslateError(oauth.ErrTokenExchange, "work")
	var typed *errx.Error
	if !errors.As(translated, &typed) || typed.Code != errx.CodeAuth || typed.Reason != "OAUTH_TOKEN_EXCHANGE_FAILED" {
		t.Fatalf("translation=%#v", typed)
	}
}

func TestRefreshFailureKeepsLegacyNonRetryableEnvelope(t *testing.T) {
	issuer := "https://hub.example.test"
	client, err := oauth.NewClient(oauth.Config{
		IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath,
		TokenURL: issuer + endpoint.OAuthTokenPath, ClientID: "client", Scopes: []string{"YouTrack"},
		RedirectURI: "http://127.0.0.1:18987/oauth/callback",
	}, oauthDiagnosticTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("server-secret-sentinel")), Header: make(http.Header)}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Refresh(t.Context(), oauth.TokenSet{AccessToken: "old-access", RefreshToken: "old-refresh", TokenType: "Bearer", Scopes: []string{"YouTrack"}})
	if err != oauth.ErrTokenExchange {
		t.Fatalf("refresh error=%v, want published non-retryable sentinel", err)
	}
	translated := TranslateError(err, "work")
	if errx.ExitCode(translated) != errx.CodeAuth {
		t.Fatalf("refresh exit=%d, want auth", errx.ExitCode(translated))
	}
	var stdout bytes.Buffer
	if exit := (&output.Writer{Format: output.FormatJSON, Out: &stdout, Err: io.Discard}).Failure(translated); exit != errx.CodeAuth {
		t.Fatalf("rendered refresh exit=%d, want auth", exit)
	}
	var envelope output.Envelope
	if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error == nil || envelope.Error.Code != "OAUTH_TOKEN_EXCHANGE_FAILED" || envelope.Error.RetryAfter != "" || strings.Contains(strings.ToLower(envelope.Hint), "retry") {
		t.Fatalf("refresh envelope advertises retry: %+v", envelope)
	}
	if strings.Contains(stdout.String(), "server-secret-sentinel") {
		t.Fatalf("refresh envelope leaked untrusted response: %q", stdout.String())
	}
}
