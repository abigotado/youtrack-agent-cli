// Package endpoint validates the fixed, non-secret URL topology used by a
// YouTrack profile. It never performs discovery or network I/O.
package endpoint

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	MaxURLLength = 2048

	OAuthAuthorizationPath = "/api/rest/oauth2/auth"
	OAuthTokenPath         = "/api/rest/oauth2/token"
	RESTPath               = "/api"
	MCPPath                = "/mcp"
)

var ErrInvalidEndpoint = errors.New("invalid endpoint")

var readOnlyMCPTools = [...]string{
	"get_current_user",
	"search_issues",
	"get_issue",
	"get_issue_comments",
	"get_project",
	"get_issue_fields_schema",
}

// ReadOnlyMCPTools returns a defensive copy of the exact approved tool list.
func ReadOnlyMCPTools() []string {
	return append([]string(nil), readOnlyMCPTools[:]...)
}

// ValidateServiceURL accepts a canonical HTTPS origin with an optional
// YouTrack base path, for example https://tracker.example or
// https://example.test/youtrack. Query strings and trailing slashes are
// rejected so every derived endpoint has one representation.
func ValidateServiceURL(raw string) error {
	parsed, err := parsePinnedHTTPS(raw)
	if err != nil {
		return err
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return invalid("service URL must not contain a query")
	}
	if parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") {
		return invalid("service URL must not end with a slash")
	}
	return validateCanonicalPath(parsed.Path)
}

// ValidateApprovalURL enforces the language-neutral URL grammar understood by
// both the Go plan authority and the native approval boundary. It performs no
// DNS resolution or network I/O.
func ValidateApprovalURL(raw string) error {
	parsed, err := parseApprovalHTTPS(raw)
	if err != nil {
		return err
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return invalid("approval URL must not contain a query")
	}
	return nil
}

// ValidateApprovalRESTBaseURL requires the strict approval-plane REST base to
// be derived exactly from the strict instance URL. It is intentionally
// separate from the backward-compatible profile-plane validator.
func ValidateApprovalRESTBaseURL(instanceURL, restBaseURL string) error {
	if err := ValidateApprovalURL(instanceURL); err != nil {
		return fmt.Errorf("instance URL: %w", err)
	}
	if restBaseURL != instanceURL+RESTPath {
		return invalid("REST base URL must equal instance_url + %s", RESTPath)
	}
	if err := ValidateApprovalURL(restBaseURL); err != nil {
		return fmt.Errorf("REST base URL: %w", err)
	}
	return nil
}

// ValidateRESTBaseURL requires the REST base to be derived exactly from the
// separately pinned service URL. This prevents a credential from being sent
// to a lookalike REST origin or base path.
func ValidateRESTBaseURL(serviceURL, restBaseURL string) error {
	if err := ValidateServiceURL(serviceURL); err != nil {
		return fmt.Errorf("service URL: %w", err)
	}
	if restBaseURL != serviceURL+RESTPath {
		return invalid("REST base URL must equal service_url + %s", RESTPath)
	}
	parsed, err := parsePinnedHTTPS(restBaseURL)
	if err != nil {
		return err
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return invalid("REST base URL must not contain a query")
	}
	return nil
}

// ValidateMCPURL requires the exact positive read-tool set and schema output.
// A bare endpoint, ignoreTools, missing names, or any additional tool fails
// closed. Tool order is canonicalized by CanonicalMCPURL rather than trusted.
func ValidateMCPURL(serviceURL, mcpURL string) error {
	want, err := CanonicalMCPURL(serviceURL)
	if err != nil {
		return err
	}
	parsed, err := parsePinnedHTTPS(mcpURL)
	if err != nil {
		return err
	}
	service, _ := url.Parse(serviceURL)
	if parsed.Scheme != service.Scheme || parsed.Host != service.Host || parsed.Path != service.Path+MCPPath {
		return invalid("MCP URL must use the pinned service origin and service_url + %s path", MCPPath)
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return invalid("MCP query is malformed")
	}
	if len(values) != 2 || len(values["tools"]) != 1 || len(values["enableToolOutputSchema"]) != 1 {
		return invalid("MCP query must contain exactly tools and enableToolOutputSchema once")
	}
	if values.Get("enableToolOutputSchema") != "true" {
		return invalid("enableToolOutputSchema must be true")
	}
	tools := strings.Split(values.Get("tools"), ",")
	if !sameToolSet(tools, readOnlyMCPTools[:]) {
		return invalid("tools must contain exactly the approved six read tools")
	}
	if mcpURL != want {
		return invalid("MCP URL is not in canonical form")
	}
	return nil
}

// CanonicalMCPURL returns the only accepted read-plane URL representation.
func CanonicalMCPURL(serviceURL string) (string, error) {
	if err := ValidateServiceURL(serviceURL); err != nil {
		return "", fmt.Errorf("service URL: %w", err)
	}
	return serviceURL + MCPPath + "?tools=" + strings.Join(readOnlyMCPTools[:], ",") + "&enableToolOutputSchema=true", nil
}

// ValidateOAuthTopology pins an issuer and the two public-client endpoints.
// External Hub is supported because the issuer is independent from the
// YouTrack service URL, but both OAuth endpoints must derive from that issuer.
func ValidateOAuthTopology(issuerURL, authorizationURL, tokenURL string) error {
	if err := ValidateServiceURL(issuerURL); err != nil {
		return fmt.Errorf("OAuth issuer: %w", err)
	}
	if authorizationURL != issuerURL+OAuthAuthorizationPath {
		return invalid("OAuth authorization URL must equal issuer_url + %s", OAuthAuthorizationPath)
	}
	if tokenURL != issuerURL+OAuthTokenPath {
		return invalid("OAuth token URL must equal issuer_url + %s", OAuthTokenPath)
	}
	if _, err := parsePinnedHTTPS(authorizationURL); err != nil {
		return fmt.Errorf("OAuth authorization URL: %w", err)
	}
	if _, err := parsePinnedHTTPS(tokenURL); err != nil {
		return fmt.Errorf("OAuth token URL: %w", err)
	}
	return nil
}

// ValidateLoopbackRedirect accepts only an exact HTTP loopback callback with
// a fixed non-root path and explicit non-privileged port. Hostnames such as
// localhost are intentionally rejected to avoid DNS and hosts-file ambiguity.
func ValidateLoopbackRedirect(raw string) error {
	if raw == "" || len(raw) > MaxURLLength || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t") {
		return invalid("OAuth redirect URI is empty, oversized, or contains whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return invalid("parse OAuth redirect URI: %v", err)
	}
	if parsed.Scheme != "http" || parsed.Opaque != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return invalid("OAuth redirect URI must be an exact HTTP loopback URL without credentials, query, or fragment")
	}
	ip := net.ParseIP(parsed.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return invalid("OAuth redirect URI host must be a numeric loopback address")
	}
	port, err := strconv.Atoi(parsed.Port())
	if err != nil || port < 1024 || port > 65535 {
		return invalid("OAuth redirect URI must use an explicit port from 1024 through 65535")
	}
	if parsed.Path == "" || parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") {
		return invalid("OAuth redirect URI must contain a fixed non-root callback path")
	}
	if err := validateCanonicalPath(parsed.Path); err != nil {
		return err
	}
	if parsed.String() != raw {
		return invalid("OAuth redirect URI is not in canonical form")
	}
	return nil
}

func parsePinnedHTTPS(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > MaxURLLength || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n\t") {
		return nil, invalid("URL is empty, oversized, or contains whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, invalid("parse URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return nil, invalid("URL must be absolute HTTPS without credentials or fragment")
	}
	if parsed.Host != strings.ToLower(parsed.Host) {
		return nil, invalid("URL host must be lowercase")
	}
	if strings.HasSuffix(parsed.Host, ".") {
		return nil, invalid("URL host must not have a trailing dot")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, invalid("URL port is invalid")
		}
	}
	if parsed.String() != raw {
		return nil, invalid("URL is not in canonical form")
	}
	if err := validateCanonicalPath(parsed.Path); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateCanonicalPath(path string) error {
	if strings.Contains(path, "//") || strings.Contains(path, "%") || strings.ContainsAny(path, "\\\x00\r\n\t") {
		return invalid("URL path is not canonical")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return invalid("URL path must not contain dot segments")
		}
	}
	return nil
}

func parseApprovalHTTPS(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > MaxURLLength || !hasOnlyASCIIURLBytes(raw) || strings.Contains(raw, "%") {
		return nil, invalid("URL is empty, oversized, or contains percent encoding, non-ASCII, control, or space bytes")
	}
	if !strings.HasPrefix(raw, "https://") {
		return nil, invalid("URL must start with literal lowercase https://")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, invalid("parse URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" || parsed.Fragment != "" {
		return nil, invalid("URL must be absolute HTTPS without credentials or fragment")
	}
	if err := validateCanonicalAuthority(parsed.Host); err != nil {
		return nil, err
	}
	if parsed.String() != raw {
		return nil, invalid("URL is not in canonical form")
	}
	if err := validateApprovalPath(parsed.Path); err != nil {
		return nil, err
	}
	return parsed, nil
}

func validateApprovalPath(path string) error {
	if path == "" {
		return nil
	}
	if path[0] != '/' || path == "/" || strings.HasSuffix(path, "/") || strings.Contains(path, "//") {
		return invalid("URL path must be empty or contain nonempty slash-prefixed segments")
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return invalid("URL path must not contain dot segments")
		}
	}
	for index := 1; index < len(path); index++ {
		if path[index] == '/' {
			continue
		}
		if !isApprovalPathByte(path[index]) {
			return invalid("URL path contains a byte outside the canonical ASCII alphabet")
		}
	}
	return nil
}

func validateCanonicalAuthority(authority string) error {
	if authority == "" || authority != strings.ToLower(authority) || strings.ContainsAny(authority, "[]") || strings.Count(authority, ":") > 1 {
		return invalid("URL host must be canonical lowercase DNS or dotted IPv4")
	}
	host, port, hasPort := authority, "", false
	if index := strings.LastIndexByte(authority, ':'); index >= 0 {
		host, port, hasPort = authority[:index], authority[index+1:], true
	}
	if !validateCanonicalIPv4(host) && !validateCanonicalDNSName(host) {
		return invalid("URL host must be canonical lowercase DNS or dotted IPv4")
	}
	if looksLikeDottedIPv4(host) && !validateCanonicalIPv4(host) {
		return invalid("dotted IPv4 host is not canonical")
	}
	if hasPort {
		if port == "" || !isASCIIDecimal(port) || (len(port) > 1 && port[0] == '0') {
			return invalid("URL port is empty or has a leading zero")
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || value == 443 {
			return invalid("URL port must be 1 through 65535 and omit the default 443")
		}
	}
	return nil
}

func isASCIIDecimal(value string) bool {
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return value != ""
}

func validateCanonicalDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			value := label[index]
			if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '-' {
				return false
			}
		}
	}
	return true
}

func validateCanonicalIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for index := range len(part) {
			if part[index] < '0' || part[index] > '9' {
				return false
			}
		}
		value, err := strconv.Atoi(part)
		if err != nil || value > 255 {
			return false
		}
	}
	return true
}

func looksLikeDottedIPv4(host string) bool {
	if strings.Count(host, ".") != 3 {
		return false
	}
	for index := range len(host) {
		if (host[index] < '0' || host[index] > '9') && host[index] != '.' {
			return false
		}
	}
	return true
}

func hasOnlyASCIIURLBytes(raw string) bool {
	for index := range len(raw) {
		if raw[index] < 0x21 || raw[index] > 0x7e {
			return false
		}
	}
	return true
}

func isApprovalPathByte(value byte) bool {
	if (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') {
		return true
	}
	return strings.ContainsRune("-._~!$&'()*+,;=:@", rune(value))
}

func sameToolSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	left := append([]string(nil), actual...)
	right := append([]string(nil), expected...)
	sort.Strings(left)
	sort.Strings(right)
	for index := range left {
		if left[index] == "" || left[index] != right[index] || (index > 0 && left[index] == left[index-1]) {
			return false
		}
	}
	return true
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidEndpoint, fmt.Sprintf(format, args...))
}
