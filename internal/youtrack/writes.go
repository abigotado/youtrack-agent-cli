package youtrack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const (
	maxSummaryBytes     = 1024
	maxDescriptionBytes = 1 << 20
	maxMutationBodySize = 2 << 20
)

// CustomFieldUpdate is one ID- and type-bound issue custom field mutation.
// Value must be exactly one bounded JSON value.
type CustomFieldUpdate struct {
	ID    string          `json:"id"`
	Type  string          `json:"$type"`
	Value json.RawMessage `json:"value"`
}

// CreateIssueInput is the complete supported issue.create payload.
type CreateIssueInput struct {
	ProjectID    string
	Summary      string
	Description  *string
	CustomFields []CustomFieldUpdate
}

// UpdateIssueInput is the complete supported issue.update payload. ProjectID
// and ProjectKey bind the result to the REST best-effort policy preflight and
// are never sent as mutation fields, so this operation cannot move an issue.
type UpdateIssueInput struct {
	IssueID      string
	ProjectID    string
	ProjectKey   string
	Summary      *string
	Description  *string
	CustomFields []CustomFieldUpdate
}

type createIssuePayload struct {
	Project      projectReference    `json:"project"`
	Summary      string              `json:"summary"`
	Description  *string             `json:"description,omitempty"`
	CustomFields []CustomFieldUpdate `json:"customFields,omitempty"`
}

type updateIssuePayload struct {
	Summary      *string             `json:"summary,omitempty"`
	Description  *string             `json:"description,omitempty"`
	CustomFields []CustomFieldUpdate `json:"customFields,omitempty"`
}

type projectReference struct {
	ID string `json:"id"`
}

// ValidateCreateIssueInput validates create intent without credentials or
// network access.
func ValidateCreateIssueInput(input CreateIssueInput) error {
	if err := validateIdentifier("project", input.ProjectID); err != nil {
		return err
	}
	if err := validateRequiredText("summary", input.Summary, maxSummaryBytes); err != nil {
		return err
	}
	if input.Description != nil {
		if err := validateOptionalText("description", *input.Description, maxDescriptionBytes); err != nil {
			return err
		}
	}
	return validateCustomFieldUpdates(input.CustomFields)
}

// ValidateUpdateIssueInput validates update intent without credentials or
// network access.
func ValidateUpdateIssueInput(input UpdateIssueInput) error {
	if err := validateIdentifier("issue", input.IssueID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectID); err != nil {
		return err
	}
	if err := validateIdentifier("project", input.ProjectKey); err != nil {
		return err
	}
	if input.Summary == nil && input.Description == nil && len(input.CustomFields) == 0 {
		return errx.Usage("issue update must change at least one supported field")
	}
	if input.Summary != nil {
		if err := validateRequiredText("summary", *input.Summary, maxSummaryBytes); err != nil {
			return err
		}
	}
	if input.Description != nil {
		if err := validateOptionalText("description", *input.Description, maxDescriptionBytes); err != nil {
			return err
		}
	}
	return validateCustomFieldUpdates(input.CustomFields)
}

// CreateIssue dispatches exactly one non-replayable POST /api/issues request.
func (client *Client) CreateIssue(ctx context.Context, input CreateIssueInput) (Issue, error) {
	if err := ValidateCreateIssueInput(input); err != nil {
		return Issue{}, err
	}
	payload := createIssuePayload{
		Project: projectReference{ID: input.ProjectID}, Summary: input.Summary,
		Description: input.Description, CustomFields: input.CustomFields,
	}
	var result Issue
	if err := client.sendMutation(ctx, "/issues", "issue.create", payload, &result); err != nil {
		return Issue{}, err
	}
	if validateIssueResponse(result, "") != nil || result.Project.ID != input.ProjectID || result.Summary != input.Summary {
		return Issue{}, errx.WriteOutcomeUnknown("issue.create")
	}
	return result, nil
}

// UpdateIssue dispatches exactly one non-replayable POST for the exact issue.
// It is classified rest-best-effort because a project move can race the local
// preflight and this HTTP request.
func (client *Client) UpdateIssue(ctx context.Context, input UpdateIssueInput) (Issue, error) {
	if err := ValidateUpdateIssueInput(input); err != nil {
		return Issue{}, err
	}
	payload := updateIssuePayload{
		Summary: input.Summary, Description: input.Description, CustomFields: input.CustomFields,
	}
	var result Issue
	if err := client.sendMutation(ctx, "/issues/"+url.PathEscape(input.IssueID), "issue.update", payload, &result); err != nil {
		return Issue{}, err
	}
	if validateIssueResponse(result, input.IssueID) != nil || result.Project.ID != input.ProjectID || result.Project.ShortName != input.ProjectKey {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	if input.Summary != nil && result.Summary != *input.Summary {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	if input.Description != nil && (result.Description == nil || *result.Description != *input.Description) {
		return Issue{}, errx.WriteOutcomeUnknown("issue.update")
	}
	return result, nil
}

func (client *Client) sendMutation(ctx context.Context, operationPath, operation string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errx.Internal("could not encode the typed YouTrack mutation")
	}
	if len(body) > maxMutationBodySize {
		return errx.Usage("typed mutation body exceeds the %d-byte safety limit", maxMutationBodySize)
	}
	return client.writeJSON(ctx, request{
		method: http.MethodPost, path: operationPath, query: fieldsQuery(issueFields),
		body: body, operation: operation, write: true,
	}, out)
}

func validateCustomFieldUpdates(fields []CustomFieldUpdate) error {
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if err := validateIdentifier("custom field", field.ID); err != nil {
			return err
		}
		if err := validateTypeName(field.Type); err != nil {
			return err
		}
		if _, exists := seen[field.ID]; exists {
			return errx.Usage("custom field IDs must be unique")
		}
		seen[field.ID] = struct{}{}
		if len(field.Value) == 0 || len(field.Value) > maxCustomFieldValueSize {
			return errx.Usage("custom field value must be one bounded JSON value")
		}
		decoder := json.NewDecoder(bytes.NewReader(field.Value))
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return errx.Usage("custom field value must be valid JSON")
		}
		var extra json.RawMessage
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return errx.Usage("custom field value must contain exactly one JSON value")
		}
	}
	return nil
}

func validateTypeName(value string) error {
	if value == "" || len(value) > maxIdentifierBytes {
		return errx.Usage("custom field type is invalid")
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return errx.Usage("custom field type is invalid")
	}
	return nil
}

func validateRequiredText(name, value string, limit int) error {
	if strings.TrimSpace(value) == "" {
		return errx.Usage("%s is required", name)
	}
	return validateOptionalText(name, value, limit)
}

func validateOptionalText(name, value string, limit int) error {
	if !utf8.ValidString(value) || len(value) > limit || strings.ContainsRune(value, '\x00') {
		return errx.Usage("%s must be valid UTF-8 no longer than %d bytes", name, limit)
	}
	return nil
}
