// Package operatorwrite defines the separate, lower-assurance operator-confirmed
// write lane. Its consumption ledger prevents cooperative crash/concurrent replay;
// it does not prove human presence or resist a malicious process with the same UID.
package operatorwrite

import "time"

const (
	Version          = 1
	Lane             = "operator-write-v1"
	ConfirmationMode = "operator_confirmed"
	Notifications    = "youtrack-default"
	PlanIDPrefix     = "YTOW-"
	PlanTTL          = 15 * time.Minute
	// Caps apply to complete JSON inputs/records, including escaping and metadata.
	MaxSnapshotBytes = 24 * 1024
	MaxRequestBytes  = 256 * 1024
	MaxPlanBytes     = 256 * 1024
	MaxRecordBytes   = 512 * 1024
	// MaxCommentBytes includes the visible operator marker added by Prepare.
	MaxCommentBytes = 32 * 1024
)

type Kind string

const (
	KindIssueUpdate Kind = "issue.update"
	KindCommentAdd  Kind = "comment.add"
)

type Binding struct {
	ProfileName                string `json:"profile_name"`
	ProfileIdentitySHA256      string `json:"profile_identity_sha256"`
	CredentialGeneration       string `json:"credential_generation"`
	AccountID                  string `json:"account_id"`
	AccountLogin               string `json:"account_login"`
	InstanceURL                string `json:"instance_url"`
	RESTBaseURL                string `json:"rest_base_url"`
	MCPURL                     string `json:"mcp_url"`
	OAuthClientID              string `json:"oauth_client_id"`
	OAuthIssuerURL             string `json:"oauth_issuer_url"`
	OAuthAuthorizationEndpoint string `json:"oauth_authorization_endpoint"`
	OAuthTokenEndpoint         string `json:"oauth_token_endpoint"`
	PolicySHA256               string `json:"policy_sha256"`
	PolicyRevision             uint64 `json:"policy_revision"`
}

type Issue struct {
	ID         string `json:"id"`
	ReadableID string `json:"readable_id"`
	ProjectID  string `json:"project_id"`
	ProjectKey string `json:"project_key"`
	Updated    int64  `json:"updated"`
}

type Value struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Archived bool   `json:"archived"`
}

// Field freezes only the touched field projection and selected target value.
type Field struct {
	IssueFieldID     string `json:"issue_field_id"`
	ProjectFieldID   string `json:"project_field_id"`
	GlobalFieldID    string `json:"global_field_id"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	ProjectFieldType string `json:"project_field_type"`
	ValueType        string `json:"value_type"`
	FieldTypeID      string `json:"field_type_id"`
	FieldTypeType    string `json:"field_type_type"`
	IsMultiValue     bool   `json:"is_multi_value"`
	BundleID         string `json:"bundle_id"`
	BundleType       string `json:"bundle_type"`
	CanBeEmpty       bool   `json:"can_be_empty"`
	IsPublic         bool   `json:"is_public"`
	CurrentValue     *Value `json:"current_value"`
	TargetValue      Value  `json:"target_value"`
}

type Snapshot struct {
	Version    int       `json:"version"`
	Lane       string    `json:"lane"`
	Kind       Kind      `json:"kind"`
	Binding    Binding   `json:"binding"`
	Issue      Issue     `json:"issue"`
	Field      *Field    `json:"field,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
}

type Request struct {
	Kind        Kind   `json:"kind"`
	CommentText string `json:"comment_text,omitempty"`
}

type Plan struct {
	Version          int       `json:"version"`
	Lane             string    `json:"lane"`
	ID               string    `json:"id"`
	ConfirmationMode string    `json:"confirmation_mode"`
	Notifications    string    `json:"notifications"`
	Snapshot         Snapshot  `json:"snapshot"`
	Request          Request   `json:"request"`
	CreatedAt        time.Time `json:"created_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	SHA256           string    `json:"sha256"`
}

type State string

const (
	StatePrepared         State = "prepared"
	StateInFlight         State = "in_flight"
	StateApplied          State = "applied"
	StateUnknown          State = "unknown"
	StateRejected         State = "rejected"
	StateReconciled       State = "reconciled"
	StateOperatorRequired State = "operator_resolution_required"
)

type Attempt struct {
	ID         string    `json:"id"`
	PlanSHA256 string    `json:"plan_sha256"`
	ClaimedAt  time.Time `json:"claimed_at"`
}

type Result struct {
	State          State  `json:"state"`
	Code           string `json:"code"`
	RemoteID       string `json:"remote_id,omitempty"`
	EvidenceSHA256 string `json:"evidence_sha256,omitempty"`
}

type Record struct {
	Version int      `json:"version"`
	Plan    Plan     `json:"plan"`
	State   State    `json:"state"`
	Attempt *Attempt `json:"attempt,omitempty"`
	Result  *Result  `json:"result,omitempty"`
}

func (r Record) NonReplayable() bool { return r.State != StatePrepared || r.Attempt != nil }
