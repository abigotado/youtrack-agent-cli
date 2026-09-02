package endpoint

import (
	"errors"
	"net/url"
	"testing"
)

func TestValidateServiceTopology(t *testing.T) {
	service := "https://tracker.example.test/youtrack"
	mcp, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatalf("CanonicalMCPURL() error = %v", err)
	}
	tests := []struct {
		name string
		fn   func() error
		ok   bool
	}{
		{name: "service with base path", fn: func() error { return ValidateServiceURL(service) }, ok: true},
		{name: "root service", fn: func() error { return ValidateServiceURL("https://tracker.example.test") }, ok: true},
		{name: "REST derived exactly", fn: func() error { return ValidateRESTBaseURL(service, service+"/api") }, ok: true},
		{name: "MCP exact allowlist", fn: func() error { return ValidateMCPURL(service, mcp) }, ok: true},
		{name: "HTTP rejected", fn: func() error { return ValidateServiceURL("http://tracker.example.test") }},
		{name: "userinfo rejected", fn: func() error { return ValidateServiceURL("https://user@tracker.example.test") }},
		{name: "query rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test?x=1") }},
		{name: "trailing slash rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/") }},
		{name: "dot segment rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/./youtrack") }},
		{name: "parent segment rejected", fn: func() error { return ValidateServiceURL("https://tracker.example.test/youtrack/../other") }},
		{name: "REST other origin rejected", fn: func() error { return ValidateRESTBaseURL(service, "https://other.example.test/api") }},
		{name: "bare MCP rejected", fn: func() error { return ValidateMCPURL(service, service+"/mcp") }},
		{name: "ignoreTools rejected", fn: func() error { return ValidateMCPURL(service, service+"/mcp?ignoreTools=create_issue") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.fn()
			if test.ok && err != nil {
				t.Fatalf("validation error = %v", err)
			}
			if !test.ok && !errors.Is(err, ErrInvalidEndpoint) {
				t.Fatalf("validation error = %v, want ErrInvalidEndpoint", err)
			}
		})
	}
}

func TestValidateMCPURLFailsClosedOnToolChanges(t *testing.T) {
	service := "https://tracker.example.test"
	canonical, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	queries := []url.Values{
		{"tools": {"get_issue"}, "enableToolOutputSchema": {"true"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema,update_issue"}, "enableToolOutputSchema": {"true"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema"}},
		{"tools": {"get_current_user,search_issues,get_issue,get_issue_comments,get_project,get_issue_fields_schema"}, "enableToolOutputSchema": {"false"}},
	}
	for _, query := range queries {
		candidate := *parsed
		candidate.RawQuery = query.Encode()
		if err := ValidateMCPURL(service, candidate.String()); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateMCPURL(%q) error = %v", candidate.String(), err)
		}
	}
}

func TestReadOnlyMCPToolsReturnsDefensiveCopy(t *testing.T) {
	service := "https://tracker.example.test"
	want, err := CanonicalMCPURL(service)
	if err != nil {
		t.Fatal(err)
	}
	tools := ReadOnlyMCPTools()
	tools[0] = "update_issue"
	got, err := CanonicalMCPURL(service)
	if err != nil || got != want {
		t.Fatalf("canonical URL changed through exposed copy: got=%q err=%v", got, err)
	}
}

func TestValidateOAuthTopologyAndRedirect(t *testing.T) {
	issuer := "https://hub.example.test/hub"
	if err := ValidateOAuthTopology(issuer, issuer+OAuthAuthorizationPath, issuer+OAuthTokenPath); err != nil {
		t.Fatalf("ValidateOAuthTopology() error = %v", err)
	}
	if err := ValidateOAuthTopology(issuer, "https://lookalike.example.test/api/rest/oauth2/auth", issuer+OAuthTokenPath); !errors.Is(err, ErrInvalidEndpoint) {
		t.Fatalf("wrong authorization endpoint error = %v", err)
	}
	for _, redirect := range []string{"http://127.0.0.1:18987/oauth/callback", "http://[::1]:18987/oauth/callback"} {
		if err := ValidateLoopbackRedirect(redirect); err != nil {
			t.Fatalf("ValidateLoopbackRedirect(%q) error = %v", redirect, err)
		}
	}
	for _, redirect := range []string{
		"https://127.0.0.1:18987/oauth/callback",
		"http://localhost:18987/oauth/callback",
		"http://127.0.0.1/oauth/callback",
		"http://127.0.0.1:18987/oauth/callback?code=x",
	} {
		if err := ValidateLoopbackRedirect(redirect); !errors.Is(err, ErrInvalidEndpoint) {
			t.Fatalf("ValidateLoopbackRedirect(%q) error = %v", redirect, err)
		}
	}
}
