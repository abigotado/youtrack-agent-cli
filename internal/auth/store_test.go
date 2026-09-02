package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

func authTestProfile(t *testing.T) profile.Profile {
	t.Helper()
	service := "https://tracker.example.test"
	mcp, err := endpoint.CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://hub.example.test"
	value := profile.Profile{Name: "work", ServiceURL: service, RESTBaseURL: service + "/api", MCPURL: mcp,
		OAuth: profile.OAuthConfig{IssuerURL: issuer, AuthorizationURL: issuer + endpoint.OAuthAuthorizationPath, TokenURL: issuer + endpoint.OAuthTokenPath,
			ClientID: "client", Scopes: []string{"YouTrack"}, RedirectURI: "http://127.0.0.1:18987/oauth/callback"},
		ExpectedAccountID: "1-42", ExpectedLogin: "alice", Capabilities: []profile.Capability{profile.CapabilityRead, profile.CapabilityIssueUpdate},
		Executor: profile.ExecutorRESTBestEffort, Assurance: profile.AssuranceBestEffort}
	bound, err := value.WithNewCredentialGeneration()
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestCredentialPayloadRoundTripKindsAndRedaction(t *testing.T) {
	selected := authTestProfile(t)
	credentials := []Credential{
		{Kind: CredentialPermanentToken, PermanentToken: "permanent-sentinel"},
		{Kind: CredentialOAuth, AccessToken: "access-sentinel", RefreshToken: "refresh-sentinel", TokenType: "Bearer", AccessTokenExpiresAt: time.Now().Add(time.Hour).UTC()},
	}
	for _, candidate := range credentials {
		bound, err := BindCredential(candidate, selected)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeCredentialValue(bound)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeCredentialValue(encoded)
		if err != nil || ValidateCredentialBinding(decoded, selected) != nil {
			t.Fatalf("decode error=%v credential=%v", err, decoded)
		}
		for _, secret := range []string{candidate.PermanentToken, candidate.AccessToken, candidate.RefreshToken} {
			if secret == "" {
				continue
			}
			if strings.Contains(fmt.Sprintf("%v", decoded), secret) {
				t.Fatal("format exposed secret")
			}
			raw, err := json.Marshal(decoded)
			if err != nil || strings.Contains(string(raw), secret) {
				t.Fatal("JSON exposed secret")
			}
		}
	}
}

func TestCredentialBindingFailsClosed(t *testing.T) {
	selected := authTestProfile(t)
	bound, err := BindCredential(Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}, selected)
	if err != nil {
		t.Fatal(err)
	}
	changed := selected
	changed.ExpectedLogin = "bob"
	if err := ValidateCredentialBinding(bound, changed); err != ErrCredentialBindingMismatch {
		t.Fatalf("binding error=%v", err)
	}
}

func TestCredentialPayloadRejectsLegacyAndUnknown(t *testing.T) {
	for _, raw := range [][]byte{[]byte("legacy-token"), append([]byte(credentialPayloadPrefix), []byte(`{"version":1,"unknown":true}`)...)} {
		if _, err := decodeCredentialValue(raw); err == nil {
			t.Fatalf("decode accepted %q", raw)
		}
	}
}
