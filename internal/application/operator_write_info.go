package application

import (
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
)

const (
	MaxOperatorSnapshotBytes = operatorwrite.MaxSnapshotBytes
	MaxOperatorRequestBytes  = operatorwrite.MaxRequestBytes
)

type OperatorSnapshotInput struct {
	Profile, Kind, IssueID, FieldName, ValueName, FieldID, ValueID, OutputPath string
}

type OperatorPrepareInput struct {
	Profile                   string
	SnapshotJSON, RequestJSON []byte
	OutputPath                string
	DryRun                    bool
}

type OperatorApplyInput struct {
	Profile, PlanID, ConfirmIntent string
	Yes                            bool
}
type OperatorReconcileInput struct {
	Profile, PlanID string
	Limit, Offset   int
}

// OperatorWriteInfo keeps the application boundary compact while making the
// frozen intent available for explicit review with --fields or raw output.
type OperatorWriteInfo struct {
	PlanID           string                  `json:"plan_id,omitempty"`
	State            string                  `json:"state"`
	Kind             string                  `json:"kind"`
	ConfirmationMode string                  `json:"confirmation_mode"`
	Notifications    string                  `json:"notifications"`
	ExpiresAt        string                  `json:"expires_at,omitempty"`
	IntentSHA256     string                  `json:"intent_sha256,omitempty"`
	Profile          string                  `json:"profile"`
	Instance         string                  `json:"instance"`
	AccountID        string                  `json:"account_id"`
	AccountLogin     string                  `json:"account_login"`
	IssueID          string                  `json:"issue_id"`
	ProjectID        string                  `json:"project_id"`
	ProjectKey       string                  `json:"project_key"`
	NonReplayable    bool                    `json:"non_replayable"`
	RemoteID         string                  `json:"remote_id,omitempty"`
	OutputPath       string                  `json:"output_path,omitempty"`
	Snapshot         *operatorwrite.Snapshot `json:"snapshot,omitempty"`
	Plan             *operatorwrite.Plan     `json:"plan,omitempty"`
	Evidence         string                  `json:"evidence,omitempty"`
}

func operatorSnapshotInfo(snapshot operatorwrite.Snapshot) OperatorWriteInfo {
	return OperatorWriteInfo{State: "snapshot", Kind: string(snapshot.Kind), ConfirmationMode: operatorwrite.ConfirmationMode, Notifications: operatorwrite.Notifications,
		Profile: snapshot.Binding.ProfileName, Instance: snapshot.Binding.InstanceURL, AccountID: snapshot.Binding.AccountID,
		AccountLogin: snapshot.Binding.AccountLogin, IssueID: snapshot.Issue.ID, ProjectID: snapshot.Issue.ProjectID,
		ProjectKey: snapshot.Issue.ProjectKey, Snapshot: &snapshot}
}

func operatorRecordInfo(record operatorwrite.Record) OperatorWriteInfo {
	result := operatorSnapshotInfo(record.Plan.Snapshot)
	result.Snapshot = nil
	result.PlanID, result.State, result.IntentSHA256 = record.Plan.ID, string(record.State), record.Plan.SHA256
	result.ExpiresAt = record.Plan.ExpiresAt.Format(time.RFC3339)
	result.NonReplayable, result.Plan = record.NonReplayable(), &record.Plan
	if record.Result != nil {
		result.RemoteID = record.Result.RemoteID
	}
	return result
}

// OperatorWriteSupported reports the standard build's native credential-store
// support without opening it.
func OperatorWriteSupported() bool { return operatorWriteSupported }

// OperatorBackendSupported applies an explicitly injected service backend in
// tests; production services retain the immutable platform default.
func (s *Service) OperatorBackendSupported() bool {
	if s != nil && s.OperatorWriteSupport != nil {
		return s.OperatorWriteSupport()
	}
	return operatorWriteSupported
}
