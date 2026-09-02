package application

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
)

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
