// Package oauth implements the network-safe parts of public-client OAuth:
// PKCE, callback verification, and bounded fixed-endpoint token requests. It
// does not open browsers or run a callback listener.
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
)

const maxTokenResponseBytes = 64 << 10

var (
	ErrInvalidConfig       = errors.New("invalid OAuth configuration")
	ErrInvalidCallback     = errors.New("invalid OAuth callback")
	ErrAuthorizationDenied = errors.New("OAuth authorization was denied")
	ErrTokenExchange       = errors.New("OAuth token exchange failed")
)

type Config struct {
	IssuerURL        string
	AuthorizationURL string
	TokenURL         string
	ClientID         string
	Scopes           []string
	RedirectURI      string
}

type Session struct {
	State     string
	Verifier  string
	Challenge string
}

type TokenSet struct {
	AccessToken  string    `json:"-"`
	RefreshToken string    `json:"-"`
	TokenType    string    `json:"-"`
	ExpiresAt    time.Time `json:"-"`
}

func (TokenSet) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, "<redacted>") }
func (TokenSet) LogValue() slog.Value           { return slog.StringValue("<redacted>") }

func NewSession(random io.Reader) (Session, error) {
	if random == nil {
		random = rand.Reader
	}
	state, err := randomValue(random)
	if err != nil {
		return Session{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier, err := randomValue(random)
	if err != nil {
		return Session{}, fmt.Errorf("generate PKCE verifier: %w", err)
	}
	digest := sha256.Sum256([]byte(verifier))
	return Session{State: state, Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

func randomValue(source io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func AuthorizationURL(config Config, session Session) (string, error) {
	if err := validateConfig(config); err != nil {
		return "", err
	}
	if !validSession(session) {
		return "", fmt.Errorf("%w: session is incomplete", ErrInvalidConfig)
	}
	parsed, _ := url.Parse(config.AuthorizationURL)
	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", config.ClientID)
	query.Set("redirect_uri", config.RedirectURI)
	query.Set("scope", strings.Join(config.Scopes, " "))
	query.Set("state", session.State)
	query.Set("access_type", "offline")
	query.Set("code_challenge", session.Challenge)
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validSession(session Session) bool {
	state, stateErr := base64.RawURLEncoding.DecodeString(session.State)
	verifier, verifierErr := base64.RawURLEncoding.DecodeString(session.Verifier)
	digest := sha256.Sum256([]byte(session.Verifier))
	return stateErr == nil && verifierErr == nil && len(state) == 32 && len(verifier) == 32 &&
		session.Challenge == base64.RawURLEncoding.EncodeToString(digest[:])
}

func ParseCallback(config Config, callbackURL, expectedState string) (string, error) {
	if err := validateConfig(config); err != nil {
		return "", err
	}
	expected, _ := url.Parse(config.RedirectURI)
	actual, err := url.Parse(callbackURL)
	if err != nil || actual.Scheme != expected.Scheme || actual.Host != expected.Host || actual.Path != expected.Path || actual.Fragment != "" || actual.User != nil {
		return "", ErrInvalidCallback
	}
	query, err := url.ParseQuery(actual.RawQuery)
	if err != nil {
		return "", ErrInvalidCallback
	}
	for key, values := range query {
		if (key != "code" && key != "state" && key != "error" && key != "error_description") || len(values) != 1 {
			return "", ErrInvalidCallback
		}
	}
	states := query["state"]
	if len(states) != 1 || len(states[0]) != len(expectedState) || subtle.ConstantTimeCompare([]byte(states[0]), []byte(expectedState)) != 1 {
		return "", ErrInvalidCallback
	}
	if query.Get("error") != "" {
		return "", ErrAuthorizationDenied
	}
	if query.Get("error_description") != "" {
		return "", ErrInvalidCallback
	}
	code := query["code"]
	if len(code) != 1 || code[0] == "" || len(code[0]) > 8192 {
		return "", ErrInvalidCallback
	}
	return code[0], nil
}

type Client struct {
	config Config
	http   *http.Client
	now    func() time.Time
}

func NewClient(config Config, transport http.RoundTripper) (*Client, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &Client{config: config, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OAuth redirect refused") }}, now: time.Now}, nil
}

func (client *Client) Exchange(ctx context.Context, code, verifier string) (TokenSet, error) {
	if code == "" || len(code) > 8192 || !validVerifier(verifier) {
		return TokenSet{}, ErrTokenExchange
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {client.config.RedirectURI}, "client_id": {client.config.ClientID}, "code_verifier": {verifier}}
	return client.request(ctx, form, "")
}

func validVerifier(verifier string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(verifier)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == verifier
}

func (client *Client) Refresh(ctx context.Context, current TokenSet) (TokenSet, error) {
	if current.RefreshToken == "" || len(current.RefreshToken) > 8192 {
		return TokenSet{}, ErrTokenExchange
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {current.RefreshToken}, "client_id": {client.config.ClientID}}
	return client.request(ctx, form, current.RefreshToken)
}

func (client *Client) request(ctx context.Context, form url.Values, previousRefresh string) (TokenSet, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenSet{}, ErrTokenExchange
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.http.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return TokenSet{}, ctx.Err()
		}
		return TokenSet{}, ErrTokenExchange
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponseBytes+1))
	if err != nil || len(raw) > maxTokenResponseBytes || response.StatusCode != http.StatusOK {
		return TokenSet{}, ErrTokenExchange
	}
	var wire struct {
		AccessToken  string      `json:"access_token"`
		RefreshToken string      `json:"refresh_token"`
		TokenType    string      `json:"token_type"`
		ExpiresIn    json.Number `json:"expires_in"`
		Scope        string      `json:"scope"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return TokenSet{}, ErrTokenExchange
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return TokenSet{}, ErrTokenExchange
	}
	seconds, err := strconv.ParseInt(string(wire.ExpiresIn), 10, 64)
	if err != nil || seconds <= 0 || seconds > int64((365*24*time.Hour)/time.Second) || wire.AccessToken == "" || len(wire.AccessToken) > 8192 || !strings.EqualFold(wire.TokenType, "Bearer") {
		return TokenSet{}, ErrTokenExchange
	}
	refresh := wire.RefreshToken
	if refresh == "" {
		refresh = previousRefresh
	}
	if refresh == "" || len(refresh) > 8192 {
		return TokenSet{}, ErrTokenExchange
	}
	if wire.Scope != "" && wire.Scope != strings.Join(client.config.Scopes, " ") {
		return TokenSet{}, ErrTokenExchange
	}
	return TokenSet{AccessToken: wire.AccessToken, RefreshToken: refresh, TokenType: "Bearer", ExpiresAt: client.now().Add(time.Duration(seconds) * time.Second).UTC()}, nil
}

func validateConfig(config Config) error {
	if err := endpoint.ValidateOAuthTopology(config.IssuerURL, config.AuthorizationURL, config.TokenURL); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	if config.ClientID == "" || len(config.ClientID) > 256 || strings.ContainsAny(config.ClientID, "\x00\r\n\t ") {
		return ErrInvalidConfig
	}
	if len(config.Scopes) == 0 {
		return ErrInvalidConfig
	}
	for index, scope := range config.Scopes {
		if scope == "" || strings.ContainsAny(scope, "\x00\r\n\t ") || (index > 0 && scope <= config.Scopes[index-1]) {
			return ErrInvalidConfig
		}
	}
	if err := endpoint.ValidateLoopbackRedirect(config.RedirectURI); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidConfig, err)
	}
	return nil
}
