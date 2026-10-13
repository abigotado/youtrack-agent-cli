package application

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/operatorwrite"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
	"github.com/abigotado/youtrack-agent-cli/internal/youtrack"
)

func (s *Service) requireOperatorDependencies(store bool) error {
	if !s.OperatorBackendSupported() {
		return errx.Permission("OPERATOR_WRITE_UNSUPPORTED", "operator-confirmed writes require the standard macOS CGO build")
	}
	if s == nil || s.Profiles == nil || s.Policies == nil || store && s.OperatorWrites == nil {
		return errx.Internal("operator-write local dependencies are unavailable")
	}
	return nil
}

func requireOperatorProfile(selected profile.Profile, kind operatorwrite.Kind) error {
	if selected.CredentialGeneration == "" {
		return errx.Auth("PROFILE_NOT_AUTHENTICATED", "selected profile has no bound credential generation")
	}
	if selected.Executor != profile.ExecutorRESTBestEffort || selected.Assurance != profile.AssuranceBestEffort {
		return errx.Permission("OPERATOR_EXECUTOR_REQUIRED", "operator-confirmed writes require rest-best-effort and best-effort")
	}
	var capability profile.Capability
	switch kind {
	case operatorwrite.KindIssueUpdate:
		capability = profile.CapabilityIssueUpdate
	case operatorwrite.KindCommentAdd:
		capability = profile.CapabilityCommentAdd
	default:
		return errx.Usage("unsupported operator-write kind")
	}
	if !selected.HasCapability(capability) {
		return errx.Permission("OPERATOR_CAPABILITY_REQUIRED", "selected profile does not declare the requested operator-write capability")
	}
	return nil
}

func operatorBinding(selected profile.Profile, policy writepolicy.Policy) operatorwrite.Binding {
	encoded, _ := json.Marshal(policy) // Policy contains only concrete, JSON-safe metadata.
	return operatorwrite.Binding{ProfileName: selected.Name, ProfileIdentitySHA256: profile.CredentialIdentity(selected),
		CredentialGeneration: selected.CredentialGeneration, AccountID: selected.ExpectedAccountID, AccountLogin: selected.ExpectedLogin,
		InstanceURL: selected.ServiceURL, RESTBaseURL: selected.RESTBaseURL, MCPURL: selected.MCPURL,
		OAuthClientID: selected.OAuth.ClientID, OAuthAuthorizationEndpoint: selected.OAuth.AuthorizationURL,
		OAuthTokenEndpoint: selected.OAuth.TokenURL, OAuthIssuerURL: selected.OAuth.IssuerURL,
		PolicySHA256: sha256Hex(encoded), PolicyRevision: policy.Revision}
}

func (s *Service) checkOperatorBinding(ctx context.Context, snapshot operatorwrite.Snapshot, name string) error {
	if snapshot.Binding.ProfileName != name {
		return errx.Conflict("OPERATOR_PROFILE_MISMATCH", "operator plan belongs to a different profile")
	}
	selected, err := s.Profiles.Get(ctx, name)
	if err != nil {
		return err
	}
	if err := requireOperatorProfile(selected, snapshot.Kind); err != nil {
		return err
	}
	policy, err := s.Policies.RequireProject(ctx, selected, snapshot.Issue.ProjectID, snapshot.Issue.ProjectKey)
	if err != nil {
		return err
	}
	if operatorBinding(selected, policy) != snapshot.Binding {
		return errx.Conflict("OPERATOR_BINDING_STALE", "operator profile or project policy changed after snapshot").WithHint("inspect a fresh snapshot and prepare a new intent before confirming it")
	}
	return nil
}

// SnapshotOperatorWrite reads exactly one target and its selected field schema.
// Account verification precedes issue and schema reads.
func (s *Service) SnapshotOperatorWrite(ctx context.Context, input OperatorSnapshotInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(false); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.OutputPath != "" {
		if err := operatorwrite.ValidateExportPath(ctx, input.OutputPath); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	kind := operatorwrite.Kind(input.Kind)
	selected, err := s.GetProfile(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := requireOperatorProfile(selected, kind); err != nil {
		return OperatorWriteInfo{}, err
	}
	if _, err := s.Policies.GetBound(ctx, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.IssueID == "" {
		return OperatorWriteInfo{}, errx.Usage("operator snapshot requires an exact issue ID")
	}
	if kind == operatorwrite.KindCommentAdd && (input.FieldName != "" || input.ValueName != "" || input.FieldID != "" || input.ValueID != "") {
		return OperatorWriteInfo{}, errx.Usage("comment snapshot does not accept field or value selectors")
	}
	if kind == operatorwrite.KindIssueUpdate {
		byName := input.FieldName != "" && input.ValueName != "" && input.FieldID == "" && input.ValueID == ""
		byID := input.FieldID != "" && input.ValueID != "" && input.FieldName == "" && input.ValueName == ""
		if !byName && !byID {
			return OperatorWriteInfo{}, errx.Usage("issue snapshot requires either --field and --value or --field-id and --value-id")
		}
	}
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	issue, err := client.GetIssue(ctx, input.IssueID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if issue.Project.Archived {
		return OperatorWriteInfo{}, errx.Permission("OPERATOR_PROJECT_ARCHIVED", "target issue belongs to an archived project")
	}
	policy, err := s.Policies.RequireProject(ctx, selected, issue.Project.ID, issue.Project.ShortName)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	snapshot := operatorwrite.Snapshot{Version: operatorwrite.Version, Lane: operatorwrite.Lane, Kind: kind, Binding: operatorBinding(selected, policy),
		Issue: operatorwrite.Issue{ID: issue.ID, ReadableID: issue.IDReadable, ProjectID: issue.Project.ID, ProjectKey: issue.Project.ShortName, Updated: issue.Updated}, CapturedAt: s.currentTime()}
	if kind == operatorwrite.KindIssueUpdate {
		fieldID := input.FieldID
		if fieldID == "" {
			fields, err := client.ListProjectFields(ctx, issue.Project.ID, youtrack.PageOptions{Top: 101})
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			if len(fields) > 100 {
				return OperatorWriteInfo{}, errx.Conflict("OPERATOR_SCHEMA_TRUNCATED", "bounded field lookup is truncated").WithHint("use exact --field-id and --value-id")
			}
			matches := 0
			for _, field := range fields {
				if field.Field.Name == input.FieldName {
					fieldID = field.ID
					matches++
				}
			}
			if matches != 1 {
				return OperatorWriteInfo{}, errx.Usage("field name must resolve to exactly one project field; use immutable IDs")
			}
		}
		schema, err := client.GetProjectField(ctx, issue.Project.ID, fieldID)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		if input.FieldName != "" && schema.Field.Name != input.FieldName {
			return OperatorWriteInfo{}, errx.Conflict("OPERATOR_FIELD_STALE", "selected field name changed during snapshot")
		}
		field, err := freezeOperatorField(issue, schema, input.ValueID, input.ValueName)
		if err != nil {
			return OperatorWriteInfo{}, err
		}
		snapshot.Field = &field
	}
	if err := operatorwrite.ValidateSnapshot(snapshot); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.OutputPath != "" {
		if err := operatorwrite.WriteSnapshot(ctx, input.OutputPath, snapshot); err != nil {
			return OperatorWriteInfo{}, errx.Internal("operator snapshot export failed safely")
		}
	}
	result := operatorSnapshotInfo(snapshot)
	result.OutputPath = input.OutputPath
	return result, nil
}

func freezeOperatorField(issue youtrack.Issue, schema youtrack.ProjectField, valueID, valueName string) (operatorwrite.Field, error) {
	if schema.ID == "" || schema.Field.ID == "" || schema.Field.FieldType.IsMultiValue || schema.Bundle == nil {
		return operatorwrite.Field{}, errx.Usage("only single State and Enum fields are supported")
	}
	var issueField youtrack.IssueCustomField
	matches := 0
	globalMatches := 0
	for _, field := range issue.CustomFields {
		if field.ProjectCustomField != nil && field.ProjectCustomField.Field.ID == schema.Field.ID {
			globalMatches++
		}
		if field.ProjectCustomField != nil && field.ProjectCustomField.ID == schema.ID {
			if field.ProjectCustomField.Field.ID != schema.Field.ID {
				return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "issue field does not match the global field identity")
			}
			issueField = field
			matches++
		}
	}
	if matches != 1 || globalMatches != 1 {
		return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "project field must map to exactly one issue custom field")
	}
	issueIDMatches := 0
	for _, candidate := range issue.CustomFields {
		if candidate.ID == issueField.ID {
			issueIDMatches++
		}
	}
	if issueIDMatches != 1 {
		return operatorwrite.Field{}, errx.Conflict("OPERATOR_FIELD_MAPPING_INVALID", "issue custom-field identity is duplicated")
	}
	field := operatorwrite.Field{IssueFieldID: issueField.ID, ProjectFieldID: schema.ID, GlobalFieldID: schema.Field.ID, Name: schema.Field.Name,
		Type: issueField.Type, ProjectFieldType: schema.Type, ValueType: schema.Field.FieldType.ValueType, IsMultiValue: schema.Field.FieldType.IsMultiValue,
		CanBeEmpty: schema.CanBeEmpty, IsPublic: schema.IsPublic, FieldTypeID: schema.Field.FieldType.ID, FieldTypeType: schema.Field.FieldType.Type,
		BundleID: schema.Bundle.ID, BundleType: schema.Bundle.Type}
	valueType := ""
	switch issueField.Type {
	case "StateIssueCustomField":
		valueType = "StateBundleElement"
	case "SingleEnumIssueCustomField":
		valueType = "EnumBundleElement"
	default:
		return field, errx.Usage("only single State and Enum fields are supported")
	}
	var current struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Type string `json:"$type"`
	}
	if bytes.Equal(bytes.TrimSpace(issueField.Value), []byte("null")) {
		if !schema.CanBeEmpty {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "non-empty field has a null current value")
		}
	} else {
		if err := json.Unmarshal(issueField.Value, &current); err != nil || current.ID == "" || current.Type != valueType {
			return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "current field value is not an immutable single bundle value")
		}
	}
	targetMatches, currentMatches := 0, 0
	seen := make(map[string]bool, len(schema.Bundle.Values))
	for _, value := range schema.Bundle.Values {
		if value.ID == "" || seen[value.ID] {
			return field, errx.Conflict("OPERATOR_BUNDLE_INVALID", "field bundle has missing or duplicate value IDs")
		}
		seen[value.ID] = true
		frozen := operatorwrite.Value{ID: value.ID, Name: value.Name, Archived: value.Archived, Type: value.Type}
		if value.ID == current.ID && current.ID != "" {
			field.CurrentValue = &frozen
			currentMatches++
		}
		if valueID != "" && value.ID == valueID || valueName != "" && value.Name == valueName {
			field.TargetValue = frozen
			targetMatches++
		}
	}
	if current.ID != "" && currentMatches != 1 || targetMatches != 1 || field.TargetValue.Archived {
		return field, errx.Usage("current and target values must be known and the unique target must not be archived")
	}
	if field.TargetValue.Type != valueType || field.CurrentValue != nil && field.CurrentValue.Type != valueType {
		return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "selected field values have an incompatible bundle type")
	}
	if field.CurrentValue != nil && current.Name != "" && current.Name != field.CurrentValue.Name {
		return field, errx.Conflict("OPERATOR_FIELD_VALUE_INVALID", "current field value disagrees with its bundle")
	}
	return field, nil
}

// PrepareOperatorWrite accepts bounded strict JSON and performs only local
// metadata checks. Dry-run performs no plan, ledger, or export writes.
func (s *Service) PrepareOperatorWrite(ctx context.Context, input OperatorPrepareInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(!input.DryRun); err != nil {
		return OperatorWriteInfo{}, err
	}
	if !input.DryRun && input.OutputPath != "" {
		if err := operatorwrite.ValidateExportPath(ctx, input.OutputPath); err != nil {
			return OperatorWriteInfo{}, err
		}
	}
	snapshot, err := operatorwrite.DecodeSnapshot(bytes.NewReader(input.SnapshotJSON))
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	request, err := operatorwrite.DecodeRequest(bytes.NewReader(input.RequestJSON))
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := s.checkOperatorBinding(ctx, snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	plan, err := operatorwrite.Prepare(snapshot, request, s.currentTime())
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.DryRun {
		result := operatorRecordInfo(operatorwrite.Record{Plan: plan, State: operatorwrite.StatePrepared})
		result.State = "validated_not_applied"
		return result, nil
	}
	var record operatorwrite.Record
	err = s.Profiles.WithProfileLock(ctx, input.Profile, func() error {
		return s.Policies.WithPolicyLock(ctx, input.Profile, func() error {
			if err := s.checkOperatorBinding(ctx, snapshot, input.Profile); err != nil {
				return err
			}
			var createErr error
			record, createErr = s.OperatorWrites.Create(ctx, plan)
			return createErr
		})
	})
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	result := operatorRecordInfo(record)
	if input.OutputPath != "" {
		if err := operatorwrite.WritePlan(ctx, input.OutputPath, plan); err != nil {
			return result, errx.Internal("operator plan was saved, but its exclusive export failed").WithHint("inspect operator-write status for the saved plan; choose a new export path")
		}
		result.OutputPath = input.OutputPath
	}
	return result, nil
}

// OperatorWriteStatus reads the authoritative local record without credentials.
func (s *Service) OperatorWriteStatus(ctx context.Context, id string) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	record, err := s.OperatorWrites.Get(ctx, id)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	return operatorRecordInfo(record), nil
}

// ApplyOperatorWrite verifies exact operator consent and local authorization
// before credentials, then claims the authoritative plan durably before one POST.
func (s *Service) ApplyOperatorWrite(ctx context.Context, input OperatorApplyInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	record, err := s.OperatorWrites.Get(ctx, input.PlanID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	plan := record.Plan
	if record.NonReplayable() {
		return operatorRecordInfo(record), operatorConsumedError()
	}
	if !input.Yes || input.ConfirmIntent == "" {
		return OperatorWriteInfo{}, errx.OperatorConfirmRequired()
	}
	if input.ConfirmIntent != plan.SHA256 {
		return OperatorWriteInfo{}, errx.OperatorConfirmRequired()
	}
	if err := operatorwrite.ValidatePlan(plan); err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := operatorwrite.CheckFresh(plan, s.currentTime()); err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := s.checkOperatorBinding(ctx, plan.Snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	// client takes its own profile lock and can refresh credentials; construct it
	// before the final profile -> policy -> durable-claim lock sequence.
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyOperatorRemote(ctx, client, plan.Snapshot); err != nil {
		return OperatorWriteInfo{}, err
	}
	var result operatorwrite.Record
	err = s.Profiles.WithProfileLock(ctx, input.Profile, func() error {
		return s.Policies.WithPolicyLock(ctx, input.Profile, func() error {
			if err := s.checkOperatorBinding(ctx, plan.Snapshot, input.Profile); err != nil {
				return err
			}
			if err := operatorwrite.CheckFresh(plan, s.currentTime()); err != nil {
				return err
			}
			attempt, claimErr := s.OperatorWrites.Claim(ctx, plan.ID, plan.SHA256, s.currentTime())
			if claimErr != nil {
				return claimErr
			}
			// Claim releases its own ledger lock before this remote call.
			remoteID, writeErr := dispatchOperatorWrite(ctx, client, plan)
			outcome := operatorwrite.Result{State: operatorwrite.StateApplied, Code: "WRITE_APPLIED", RemoteID: remoteID}
			if writeErr != nil {
				outcome.State, outcome.Code = operatorwrite.StateUnknown, "WRITE_OUTCOME_UNKNOWN"
				var typed *errx.Error
				if errors.As(writeErr, &typed) && typed.Reason != "WRITE_OUTCOME_UNKNOWN" {
					outcome.State, outcome.Code = operatorwrite.StateRejected, typed.Reason
				}
			}
			var finishErr error
			result, finishErr = s.OperatorWrites.Finalize(context.WithoutCancel(ctx), plan.ID, attempt, outcome, s.currentTime())
			if writeErr != nil {
				if outcome.State == operatorwrite.StateUnknown {
					return operatorUnknownError()
				}
				var typed *errx.Error
				if errors.As(writeErr, &typed) {
					clone := *typed
					clone.Hint = "this plan is consumed; inspect the issue and prepare a new intent with fresh operator confirmation before any further write"
					return &clone
				}
				return operatorUnknownError()
			}
			if finishErr != nil {
				return errx.WriteAppliedLocalFailure(string(plan.Snapshot.Kind))
			}
			return nil
		})
	})
	if result.Plan.ID == "" {
		result = record
	}
	return operatorRecordInfo(result), err
}

func verifyOperatorRemote(ctx context.Context, client *youtrack.Client, snapshot operatorwrite.Snapshot) error {
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		return err
	}
	if issue.Project.Archived || issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey || issue.Updated != snapshot.Issue.Updated {
		return errx.Conflict("OPERATOR_ISSUE_STALE", "target issue project or updated timestamp changed").WithHint("inspect a new snapshot and prepare a fresh intent")
	}
	if snapshot.Kind == operatorwrite.KindIssueUpdate {
		schema, err := client.GetProjectField(ctx, issue.Project.ID, snapshot.Field.ProjectFieldID)
		if err != nil {
			return err
		}
		field, err := freezeOperatorField(issue, schema, snapshot.Field.TargetValue.ID, "")
		if err != nil {
			return err
		}
		frozen, err := json.Marshal(snapshot.Field)
		if err != nil {
			return errx.Internal("encode frozen touched field")
		}
		fresh, err := json.Marshal(field)
		if err != nil {
			return errx.Internal("encode current touched field")
		}
		if !bytes.Equal(frozen, fresh) {
			return errx.Conflict("OPERATOR_FIELD_STALE", "touched field schema, current value, or target changed").WithHint("inspect a new snapshot and prepare a fresh intent")
		}
	}
	return nil
}

func dispatchOperatorWrite(ctx context.Context, client *youtrack.Client, plan operatorwrite.Plan) (string, error) {
	snapshot := plan.Snapshot
	if snapshot.Kind == operatorwrite.KindIssueUpdate {
		value, err := json.Marshal(struct {
			ID string `json:"id"`
		}{snapshot.Field.TargetValue.ID})
		if err != nil {
			return "", errx.Internal("encode frozen field value")
		}
		issue, err := client.UpdateIssue(ctx, youtrack.UpdateIssueInput{IssueID: snapshot.Issue.ID, ProjectID: snapshot.Issue.ProjectID, ProjectKey: snapshot.Issue.ProjectKey,
			CustomFields: []youtrack.CustomFieldUpdate{{ID: snapshot.Field.IssueFieldID, Type: snapshot.Field.Type, Value: value}}})
		return issue.ID, err
	}
	comment, err := client.AddComment(ctx, youtrack.AddCommentInput{IssueID: snapshot.Issue.ID, ExpectedAuthorID: snapshot.Binding.AccountID, ExpectedAuthorLogin: snapshot.Binding.AccountLogin, Text: plan.Request.CommentText})
	if err != nil {
		return "", err
	}
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil || issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
		return comment.ID, operatorUnknownError()
	}
	return comment.ID, nil
}

func operatorConsumedError() *errx.Error {
	return errx.Conflict("OPERATOR_PLAN_CONSUMED", "operator plan has already been consumed").WithHint("use operator-write status or reconcile; never apply this plan again")
}
func operatorUnknownError() *errx.Error {
	return errx.WriteOutcomeUnknown("operator-write").WithHint("this plan is consumed; run operator-write reconcile and request operator resolution if evidence is inconclusive; never replay this plan")
}

// ReconcileOperatorWrite collects one bounded read-only observation; it never
// restores consumed eligibility or proves a negative from absent comments.
func (s *Service) ReconcileOperatorWrite(ctx context.Context, input OperatorReconcileInput) (OperatorWriteInfo, error) {
	if err := s.requireOperatorDependencies(true); err != nil {
		return OperatorWriteInfo{}, err
	}
	if input.Limit < 1 || input.Limit > 100 || input.Offset < 0 {
		return OperatorWriteInfo{}, errx.Usage("reconcile limit must be 1-100 and offset nonnegative")
	}
	record, err := s.OperatorWrites.Get(ctx, input.PlanID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if !record.NonReplayable() || record.Attempt == nil {
		return OperatorWriteInfo{}, errx.Usage("only a consumed operator plan can be reconciled")
	}
	if record.Plan.Snapshot.Binding.ProfileName != input.Profile {
		return OperatorWriteInfo{}, errx.Conflict("OPERATOR_PROFILE_MISMATCH", "operator plan belongs to a different profile")
	}
	switch record.State {
	case operatorwrite.StateApplied, operatorwrite.StateRejected, operatorwrite.StateReconciled:
		result := operatorRecordInfo(record)
		result.Evidence = "verified_terminal_record_preserved"
		return result, nil
	case operatorwrite.StateInFlight, operatorwrite.StateUnknown, operatorwrite.StateOperatorRequired:
		// Only an unresolved consumed outcome needs remote observations.
	default:
		return OperatorWriteInfo{}, operatorConsumedError()
	}
	if err := s.checkOperatorBinding(ctx, record.Plan.Snapshot, input.Profile); err != nil {
		return OperatorWriteInfo{}, err
	}
	client, selected, err := s.client(ctx, input.Profile)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if err := verifyClientAccount(ctx, client, selected); err != nil {
		return OperatorWriteInfo{}, err
	}
	snapshot := record.Plan.Snapshot
	issue, err := client.GetIssue(ctx, snapshot.Issue.ID)
	if err != nil {
		return OperatorWriteInfo{}, err
	}
	if issue.Project.ID != snapshot.Issue.ProjectID || issue.Project.ShortName != snapshot.Issue.ProjectKey {
		return OperatorWriteInfo{}, errx.Conflict("OPERATOR_PROJECT_CHANGED", "target issue moved from the frozen project")
	}
	outcome := operatorwrite.Result{State: operatorwrite.StateOperatorRequired, Code: "OPERATOR_RESOLUTION_REQUIRED"}
	if record.Result != nil {
		outcome.RemoteID = record.Result.RemoteID
	}
	evidence := "inconclusive"
	if snapshot.Kind == operatorwrite.KindIssueUpdate {
		for _, field := range issue.CustomFields {
			if field.ID == snapshot.Field.IssueFieldID && field.Type == snapshot.Field.Type {
				var value struct {
					ID   string `json:"id"`
					Type string `json:"$type"`
				}
				if json.Unmarshal(field.Value, &value) == nil && value.ID == snapshot.Field.TargetValue.ID && value.Type == snapshot.Field.TargetValue.Type {
					evidence = "desired_value_observed_without_causal_proof"
				}
			}
		}
	} else {
		var comments []youtrack.Comment
		truncated := false
		exactFetched := false
		if record.Result != nil && record.Result.RemoteID != "" {
			comment, getErr := client.GetComment(ctx, snapshot.Issue.ID, record.Result.RemoteID)
			if getErr != nil {
				return OperatorWriteInfo{}, getErr
			}
			comments = []youtrack.Comment{comment}
			exactFetched = true
		} else {
			comments, err = client.ListComments(ctx, snapshot.Issue.ID, youtrack.PageOptions{Top: input.Limit + 1, Skip: input.Offset})
			if err != nil {
				return OperatorWriteInfo{}, err
			}
			truncated = len(comments) > input.Limit
			if truncated {
				comments = comments[:input.Limit]
			}
		}
		matches := 0
		var matchedComment youtrack.Comment
		for _, comment := range comments {
			if operatorCommentMatches(comment, record.Plan) {
				matches++
				matchedComment = comment
			}
		}
		if matches == 1 && !truncated {
			// Collection reads use the legacy shape. An exact GET verifies the
			// required deleted flag and every evidence field before success.
			verified := matchedComment
			if !exactFetched {
				var getErr error
				verified, getErr = client.GetComment(ctx, snapshot.Issue.ID, matchedComment.ID)
				if getErr != nil {
					return OperatorWriteInfo{}, getErr
				}
			}
			if operatorCommentMatches(verified, record.Plan) {
				outcome.State, outcome.Code = operatorwrite.StateReconciled, "COMMENT_OBSERVED"
				outcome.RemoteID = verified.ID
				evidence = "matching_comment_observed"
			}
		}
	}
	outcome.EvidenceSHA256 = sha256Hex([]byte(evidence))
	record, err = s.OperatorWrites.Finalize(ctx, record.Plan.ID, *record.Attempt, outcome, s.currentTime())
	if err != nil {
		return OperatorWriteInfo{}, errx.Internal("operator reconciliation evidence could not be saved")
	}
	result := operatorRecordInfo(record)
	result.Evidence = evidence
	return result, nil
}

func operatorCommentMatches(comment youtrack.Comment, plan operatorwrite.Plan) bool {
	binding := plan.Snapshot.Binding
	return comment.ID != "" && !comment.Deleted && comment.Text != nil && *comment.Text == plan.Request.CommentText &&
		strings.Contains(*comment.Text, operatorwrite.CommentMarker(plan.ID)) && comment.Author != nil && comment.Author.ID == binding.AccountID &&
		comment.Author.Login == binding.AccountLogin && comment.Visibility != nil && comment.Visibility.Type == "UnlimitedVisibility" &&
		len(comment.Visibility.PermittedGroups) == 0 && len(comment.Visibility.PermittedUsers) == 0
}
