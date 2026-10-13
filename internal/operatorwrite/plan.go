package operatorwrite

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/protocolvalue"
)

func invalid() error {
	e := errx.Usage("invalid or unsupported operator-write data")
	e.Reason = "OPERATOR_WRITE_INVALID"
	return e.WithHint("inspect the exact issue again and prepare a new operator-confirmed plan")
}

func ValidateID(id string) error {
	if protocolvalue.ValidateCanonicalBase32ID(id, PlanIDPrefix) != nil {
		return invalid()
	}
	return nil
}

func newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errx.Internal("generate operator-write identifier").Wrap(err)
	}
	return prefix + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value[:]), nil
}

func validText(s string, cap int, nonblank bool) bool {
	return len(s) <= cap && utf8.ValidString(s) && !strings.ContainsRune(s, '\x00') && (!nonblank || strings.TrimSpace(s) != "")
}

func ValidateSnapshot(s Snapshot) error {
	b := s.Binding
	if s.Version != Version || s.Lane != Lane || (s.Kind != KindIssueUpdate && s.Kind != KindCommentAdd) ||
		!protocolvalue.IsIdentifier(b.ProfileName) || !protocolvalue.IsSHA256(b.ProfileIdentitySHA256) ||
		!validGeneration(b.CredentialGeneration) || !protocolvalue.IsIdentifier(b.AccountID) || !validText(b.AccountLogin, 256, true) || strings.ContainsAny(b.AccountLogin, " \t\r\n") ||
		!protocolvalue.IsSHA256(b.PolicySHA256) || b.PolicyRevision == 0 ||
		endpoint.ValidateRESTBaseURL(b.InstanceURL, b.RESTBaseURL) != nil ||
		endpoint.ValidateMCPURL(b.InstanceURL, b.MCPURL) != nil ||
		!validText(b.OAuthClientID, 128, true) ||
		endpoint.ValidateOAuthTopology(b.OAuthIssuerURL, b.OAuthAuthorizationEndpoint, b.OAuthTokenEndpoint) != nil ||
		!protocolvalue.IsIdentifier(s.Issue.ID) || !protocolvalue.IsIdentifier(s.Issue.ReadableID) ||
		!protocolvalue.IsIdentifier(s.Issue.ProjectID) || !protocolvalue.IsProjectKey(s.Issue.ProjectKey) ||
		s.Issue.Updated <= 0 || s.CapturedAt.IsZero() || s.CapturedAt.Location() != time.UTC {
		return invalid()
	}
	if s.Kind == KindCommentAdd {
		if s.Field != nil {
			return invalid()
		}
	} else {
		f := s.Field
		if f == nil || !protocolvalue.IsIdentifier(f.IssueFieldID) || !protocolvalue.IsIdentifier(f.ProjectFieldID) ||
			!protocolvalue.IsIdentifier(f.GlobalFieldID) || !validText(f.Name, 256, true) ||
			(f.Type != "StateIssueCustomField" && f.Type != "SingleEnumIssueCustomField") ||
			f.IsMultiValue || f.FieldTypeType != "FieldType" || !protocolvalue.IsIdentifier(f.BundleID) ||
			f.FieldTypeID != f.ValueType+"[1]" ||
			f.Type == "StateIssueCustomField" && (f.ProjectFieldType != "StateProjectCustomField" || f.ValueType != "state" || f.BundleType != "StateBundle") ||
			f.Type == "SingleEnumIssueCustomField" && (f.ProjectFieldType != "EnumProjectCustomField" || f.ValueType != "enum" || f.BundleType != "EnumBundle") ||
			!validValue(f.TargetValue, f.Type) || f.TargetValue.Archived || f.CurrentValue == nil && !f.CanBeEmpty ||
			f.CurrentValue != nil && !validValue(*f.CurrentValue, f.Type) {
			return invalid()
		}
	}
	raw, err := json.Marshal(s)
	if err != nil || len(raw) > MaxSnapshotBytes {
		return invalid()
	}
	return nil
}

func validValue(v Value, fieldType string) bool {
	expected := "StateBundleElement"
	if fieldType == "SingleEnumIssueCustomField" {
		expected = "EnumBundleElement"
	}
	return protocolvalue.IsIdentifier(v.ID) && validText(v.Name, 256, true) && v.Type == expected
}

func validGeneration(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
}

// CommentMarker is public evidence for bounded reconciliation, not an approval.
func CommentMarker(id string) string { return "[youtrack operator-write " + id + "]" }

// Prepare is network-free. The supplied snapshot fixes the kind and target.
func Prepare(snapshot Snapshot, request Request, now time.Time) (Plan, error) {
	if err := ValidateSnapshot(snapshot); err != nil {
		return Plan{}, err
	}
	if request.Kind != snapshot.Kind || now.IsZero() || snapshot.CapturedAt.After(now) || now.Sub(snapshot.CapturedAt) >= PlanTTL {
		return Plan{}, invalid()
	}
	id, err := newID(PlanIDPrefix)
	if err != nil {
		return Plan{}, err
	}
	if request.Kind == KindCommentAdd {
		if !validText(request.CommentText, MaxCommentBytes, true) {
			return Plan{}, invalid()
		}
		request.CommentText += "\n\n" + CommentMarker(id)
		if len(request.CommentText) > MaxCommentBytes {
			return Plan{}, invalid()
		}
	} else if request.CommentText != "" {
		return Plan{}, invalid()
	}
	// Deep-copy the snapshot so subsequent caller edits cannot change the plan.
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return Plan{}, invalid()
	}
	var frozen Snapshot
	if err := json.Unmarshal(raw, &frozen); err != nil {
		return Plan{}, invalid()
	}
	plan := Plan{Version: Version, Lane: Lane, ID: id, ConfirmationMode: ConfirmationMode, Notifications: Notifications,
		Snapshot: frozen, Request: request, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(PlanTTL)}
	plan.SHA256, err = digest(plan)
	if err != nil {
		return Plan{}, err
	}
	return plan, ValidatePlan(plan)
}

func digest(p Plan) (string, error) {
	p.SHA256 = ""
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxPlanBytes {
		return "", invalid()
	}
	return protocolvalue.SHA256Hex(raw), nil
}

func ValidatePlan(p Plan) error {
	if p.Version != Version || p.Lane != Lane || ValidateID(p.ID) != nil || p.ConfirmationMode != ConfirmationMode ||
		p.Notifications != Notifications || ValidateSnapshot(p.Snapshot) != nil || p.Request.Kind != p.Snapshot.Kind ||
		p.CreatedAt.IsZero() || p.CreatedAt.Location() != time.UTC || p.ExpiresAt.Location() != time.UTC ||
		p.ExpiresAt.Sub(p.CreatedAt) != PlanTTL || p.Snapshot.CapturedAt.After(p.CreatedAt) ||
		p.CreatedAt.Sub(p.Snapshot.CapturedAt) >= PlanTTL || !protocolvalue.IsSHA256(p.SHA256) {
		return invalid()
	}
	if p.Request.Kind == KindCommentAdd {
		marker := "\n\n" + CommentMarker(p.ID)
		if !validText(p.Request.CommentText, MaxCommentBytes, true) || !strings.HasSuffix(p.Request.CommentText, marker) || strings.Count(p.Request.CommentText, CommentMarker(p.ID)) != 1 ||
			!validText(strings.TrimSuffix(p.Request.CommentText, marker), MaxCommentBytes, true) {
			return invalid()
		}
	} else if p.Request.CommentText != "" {
		return invalid()
	}
	sha, err := digest(p)
	if err != nil || sha != p.SHA256 {
		return invalid()
	}
	return nil
}

func CheckFresh(p Plan, now time.Time) error {
	if err := ValidatePlan(p); err != nil {
		return err
	}
	if now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) {
		return errx.Conflict("OPERATOR_PLAN_EXPIRED", "operator-write plan is outside its local lifetime").WithHint("inspect again and confirm a newly prepared plan")
	}
	return nil
}

func decode(r io.Reader, limit int, dst any) error {
	if r == nil {
		return invalid()
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil || len(raw) > limit {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return invalid()
	}
	var extra json.RawMessage
	if d.Decode(&extra) != io.EOF {
		return invalid()
	}
	// JSON duplicate keys are not canonical and could mislead a human reader.
	if hasDuplicateKeys(raw) {
		return invalid()
	}
	return nil
}

func hasDuplicateKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func() bool
	walk = func() bool {
		token, err := d.Token()
		if err != nil {
			return true
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return false
		}
		if delim == '{' {
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return true
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return true
				}
				seen[s] = true
				if walk() {
					return true
				}
			}
		} else if delim == '[' {
			for d.More() {
				if walk() {
					return true
				}
			}
		} else {
			return true
		}
		_, err = d.Token()
		return err != nil
	}
	return walk()
}

func DecodeSnapshot(r io.Reader) (Snapshot, error) {
	var s Snapshot
	if err := decode(r, MaxSnapshotBytes, &s); err != nil {
		return Snapshot{}, err
	}
	if err := ValidateSnapshot(s); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
func DecodeRequest(r io.Reader) (Request, error) {
	var q Request
	if err := decode(r, MaxRequestBytes, &q); err != nil {
		return Request{}, err
	}
	if (q.Kind != KindIssueUpdate && q.Kind != KindCommentAdd) || q.Kind == KindIssueUpdate && q.CommentText != "" ||
		q.Kind == KindCommentAdd && !validText(q.CommentText, MaxCommentBytes, true) {
		return Request{}, invalid()
	}
	return q, nil
}
func DecodePlan(r io.Reader) (Plan, error) {
	var p Plan
	if err := decode(r, MaxPlanBytes, &p); err != nil {
		return Plan{}, err
	}
	if err := ValidatePlan(p); err != nil {
		return Plan{}, err
	}
	return p, nil
}
