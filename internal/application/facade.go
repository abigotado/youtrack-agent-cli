package application

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/abigotado/youtrack-agent-cli/internal/auth"
	"github.com/abigotado/youtrack-agent-cli/internal/endpoint"
	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
	"github.com/abigotado/youtrack-agent-cli/internal/journal"
	"github.com/abigotado/youtrack-agent-cli/internal/oauth"
	"github.com/abigotado/youtrack-agent-cli/internal/profile"
	"github.com/abigotado/youtrack-agent-cli/internal/skills"
	"github.com/abigotado/youtrack-agent-cli/internal/writepolicy"
	"github.com/abigotado/youtrack-agent-cli/internal/youtrack"
)

const (
	MaxMutationRequestBytes  = intent.MaxRequestBytes
	MaxMutationExpectedBytes = intent.MaxExpectedBytes
)

type ProfileInfo struct {
	Name         string   `json:"name"`
	Instance     string   `json:"instance"`
	MCPURL       string   `json:"mcp_url"`
	AccountID    string   `json:"account_id"`
	Login        string   `json:"login"`
	Capabilities []string `json:"capabilities"`
	Executor     string   `json:"executor"`
	Assurance    string   `json:"assurance"`
}

type ProjectRef struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

type PolicyInfo struct {
	Profile        string       `json:"profile"`
	IdentitySHA256 string       `json:"identity_sha256"`
	Revision       uint64       `json:"revision"`
	Projects       []ProjectRef `json:"projects"`
}

type UserInfo struct {
	ID       string `json:"id"`
	Login    string `json:"login"`
	Name     string `json:"name,omitempty"`
	FullName string `json:"full_name,omitempty"`
	Email    string `json:"email,omitempty"`
}

type AuthStatusInfo struct {
	Profile           string    `json:"profile"`
	Instance          string    `json:"instance"`
	CredentialPresent bool      `json:"credential_present"`
	State             string    `json:"state"`
	Account           *UserInfo `json:"account,omitempty"`
}

type ProjectInfo struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
}

type IssueCustomFieldInfo struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type IssueInfo struct {
	ID            string                 `json:"id"`
	ReadableID    string                 `json:"readable_id"`
	Summary       string                 `json:"summary"`
	Description   *string                `json:"description,omitempty"`
	Project       ProjectInfo            `json:"project"`
	Reporter      *UserInfo              `json:"reporter,omitempty"`
	Created       int64                  `json:"created"`
	Updated       int64                  `json:"updated"`
	CommentsCount int                    `json:"comments_count"`
	CustomFields  []IssueCustomFieldInfo `json:"custom_fields,omitempty"`
}

type BundleValueInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Localized string `json:"localized_name,omitempty"`
	Archived  bool   `json:"archived,omitempty"`
	Type      string `json:"type"`
}

type BundleInfo struct {
	ID              string            `json:"id"`
	Values          []BundleValueInfo `json:"values,omitempty"`
	AggregatedUsers []UserInfo        `json:"aggregated_users,omitempty"`
	Type            string            `json:"type"`
}

type ProjectFieldInfo struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	ValueType    string      `json:"value_type"`
	IsMultiValue bool        `json:"is_multi_value"`
	CanBeEmpty   bool        `json:"can_be_empty"`
	IsPublic     bool        `json:"is_public"`
	Bundle       *BundleInfo `json:"bundle,omitempty"`
}

type MutationInfo struct {
	PlanID           string `json:"plan_id"`
	State            string `json:"state"`
	Revision         uint64 `json:"revision"`
	Kind             string `json:"kind"`
	Profile          string `json:"profile"`
	Instance         string `json:"instance"`
	AccountID        string `json:"account_id"`
	AccountLogin     string `json:"account_login"`
	ProjectID        string `json:"project_id"`
	ProjectKey       string `json:"project_key"`
	IntentSHA256     string `json:"intent_sha256"`
	RequestSHA256    string `json:"request_sha256"`
	ExpectedSHA256   string `json:"expected_sha256"`
	MutationAttempts uint8  `json:"mutation_attempts"`
	NonReplayable    bool   `json:"non_replayable"`
	OutputPath       string `json:"output_path,omitempty"`
}

type MutationPrepareInput struct {
	Profile      string
	Kind         string
	Project      ProjectRef
	SchemaSHA256 string
	RequestJSON  []byte
	ExpectedJSON []byte
	OutputPath   string
}

type SkillOptions struct {
	Provider   string
	Scope      string
	ProjectDir string
	Dest       string
	Confirmed  bool
	DryRun     bool
}

type SkillFileInfo struct {
	Path    string `json:"path"`
	Status  string `json:"status"`
	Applied bool   `json:"applied"`
}

type SkillResultInfo struct {
	Provider string          `json:"provider"`
	Scope    string          `json:"scope"`
	Root     string          `json:"root"`
	Skill    string          `json:"skill"`
	InSync   bool            `json:"in_sync"`
	DryRun   bool            `json:"dry_run"`
	Files    []SkillFileInfo `json:"files"`
}

func ValidateSkillOptions(opts SkillOptions) error {
	if _, err := skills.ParseProvider(opts.Provider); err != nil {
		return err
	}
	_, err := skills.ParseScope(opts.Scope)
	return err
}

func ValidateProfileName(name string) error { return profile.ValidateName(name) }

func (s *Service) ListProfileInfo(ctx context.Context) ([]ProfileInfo, error) {
	values, err := s.ListProfiles(ctx)
	result := make([]ProfileInfo, len(values))
	for index, value := range values {
		result[index] = profileInfo(value)
	}
	return result, err
}

func (s *Service) GetProfileInfo(ctx context.Context, name string) (ProfileInfo, error) {
	value, err := s.GetProfile(ctx, name)
	return profileInfo(value), err
}

func (s *Service) ValidateProfileJSON(raw []byte, requestedName string) (ProfileInfo, error) {
	var value profile.Profile
	if err := json.Unmarshal(raw, &value); err != nil {
		return ProfileInfo{}, err
	}
	if requestedName != "" && value.Name != requestedName {
		return ProfileInfo{}, errx.Usage("--profile must match the profile file name")
	}
	if err := value.ValidateLoginIntent(); err != nil {
		return ProfileInfo{}, err
	}
	return profileInfo(value), nil
}

func (s *Service) SaveProfileJSON(ctx context.Context, raw []byte, requestedName string, replace bool) (ProfileInfo, error) {
	if _, err := s.ValidateProfileJSON(raw, requestedName); err != nil {
		return ProfileInfo{}, err
	}
	var value profile.Profile
	if err := json.Unmarshal(raw, &value); err != nil {
		return ProfileInfo{}, err
	}
	saved, err := s.SaveProfile(ctx, value, replace)
	return profileInfo(saved), err
}

func (s *Service) ImportPermanentTokenReader(ctx context.Context, name string, input io.Reader, replace bool) (ProfileInfo, error) {
	if err := s.requireCredentialReplacementConfirmation(ctx, name, replace); err != nil {
		return ProfileInfo{}, err
	}
	credential, err := auth.ReadToken(input)
	if err != nil {
		return ProfileInfo{}, err
	}
	value, err := s.ImportPermanentToken(ctx, name, credential, replace)
	return profileInfo(value), err
}

func (s *Service) LoginOAuthInfo(ctx context.Context, name string, replace bool, browser Browser) (ProfileInfo, error) {
	value, err := s.LoginOAuth(ctx, name, replace, browser)
	return profileInfo(value), err
}

func (s *Service) GetAuthStatus(ctx context.Context, name string, check bool) (AuthStatusInfo, error) {
	value, err := s.AuthStatus(ctx, name, check)
	if err != nil {
		return AuthStatusInfo{}, err
	}
	result := AuthStatusInfo{Profile: value.Profile.Name, Instance: value.Profile.ServiceURL, CredentialPresent: value.CredentialPresent, State: value.State}
	if value.Account != nil {
		account := userInfo(*value.Account)
		result.Account = &account
	}
	return result, nil
}

func (s *Service) GetPolicyInfo(ctx context.Context, name string) (PolicyInfo, error) {
	value, err := s.GetPolicy(ctx, name)
	return policyInfo(value), err
}

func (s *Service) PreviewPolicyInfo(ctx context.Context, name string, projects []ProjectRef) (PolicyInfo, error) {
	value, err := s.PreviewPolicy(ctx, name, policyProjects(projects))
	return policyInfo(value), err
}

func (s *Service) SetPolicyInfo(ctx context.Context, name string, projects []ProjectRef) (PolicyInfo, error) {
	value, err := s.SetPolicy(ctx, name, policyProjects(projects))
	return policyInfo(value), err
}

func CanonicalProjects(values []ProjectRef) ([]ProjectRef, error) {
	canonical, err := writepolicy.CanonicalProjects(policyProjects(values))
	return projectRefs(canonical), err
}

func (s *Service) InspectIssueInfo(ctx context.Context, name, issueID string) (IssueInfo, ProfileInfo, error) {
	value, selected, err := s.InspectIssue(ctx, name, issueID)
	return issueInfo(value), profileInfo(selected), err
}

func (s *Service) InspectProjectInfo(ctx context.Context, name, projectID string) (ProjectInfo, ProfileInfo, error) {
	value, selected, err := s.InspectProject(ctx, name, projectID)
	return projectInfo(value), profileInfo(selected), err
}

func (s *Service) InspectSchemaInfo(ctx context.Context, name, projectID string, top, skip int) ([]ProjectFieldInfo, bool, ProfileInfo, error) {
	values, truncated, selected, err := s.InspectSchema(ctx, name, projectID, top, skip)
	result := make([]ProjectFieldInfo, len(values))
	for index, value := range values {
		result[index] = projectFieldInfo(value)
	}
	return result, truncated, profileInfo(selected), err
}

func (s *Service) PrepareMutationInfo(ctx context.Context, input MutationPrepareInput) (MutationInfo, error) {
	record, err := s.PrepareMutation(ctx, PrepareInput{
		Profile: input.Profile, Kind: intent.Kind(input.Kind), Project: writepolicy.Project{ID: input.Project.ID, Key: input.Project.Key},
		SchemaSHA256: input.SchemaSHA256, RequestJSON: input.RequestJSON, ExpectedJSON: input.ExpectedJSON, OutputPath: input.OutputPath,
	})
	return mutationInfo(record, input.OutputPath), err
}

func (s *Service) MutationStatusInfo(ctx context.Context, planID string) (MutationInfo, error) {
	record, err := s.MutationStatus(ctx, planID)
	return mutationInfo(record, ""), err
}

func (s *Service) ExportMutationInfo(ctx context.Context, planID, outputPath string) (MutationInfo, error) {
	record, err := s.ExportMutation(ctx, planID, outputPath)
	return mutationInfo(record, outputPath), err
}

func (s *Service) InstallAgentSkill(ctx context.Context, opts SkillOptions) ([]SkillResultInfo, error) {
	provider, err := skills.ParseProvider(opts.Provider)
	if err != nil {
		return nil, err
	}
	scope, err := skills.ParseScope(opts.Scope)
	if err != nil {
		return nil, err
	}
	values, err := s.InstallSkill(ctx, skills.Options{Provider: provider, Scope: scope, ProjectDir: opts.ProjectDir, Dest: opts.Dest, Confirmed: opts.Confirmed, DryRun: opts.DryRun})
	return skillResultInfo(values), err
}

func (s *Service) UninstallAgentSkill(ctx context.Context, opts SkillOptions) ([]SkillResultInfo, error) {
	provider, err := skills.ParseProvider(opts.Provider)
	if err != nil {
		return nil, err
	}
	scope, err := skills.ParseScope(opts.Scope)
	if err != nil {
		return nil, err
	}
	values, err := s.UninstallSkill(ctx, skills.Options{Provider: provider, Scope: scope, ProjectDir: opts.ProjectDir, Dest: opts.Dest, Confirmed: opts.Confirmed, DryRun: opts.DryRun})
	return skillResultInfo(values), err
}

func TranslateError(err error, name string) error {
	if err == nil {
		return nil
	}
	var typed *errx.Error
	if errors.As(err, &typed) {
		return err
	}
	switch {
	case errors.Is(err, auth.ErrLogoutIncomplete):
		return errx.Conflict("LOGOUT_INCOMPLETE", "credential removal succeeded but profile %q metadata could not be removed", name).
			WithHint("inspect the profile and credential state before retrying logout")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return errx.Translate(err)
	case errors.Is(err, profile.ErrProfileRequired):
		return errx.ProfileRequired()
	case errors.Is(err, profile.ErrInvalidProfile), errors.Is(err, endpoint.ErrInvalidEndpoint), errors.Is(err, intent.ErrInvalidPlan), errors.Is(err, intent.ErrInputTooLarge), errors.Is(err, writepolicy.ErrInvalid):
		return errx.Usage("input failed strict validation")
	case errors.Is(err, profile.ErrNotFound):
		return errx.NotFound("profile", name, nil)
	case errors.Is(err, profile.ErrAlreadyExists), errors.Is(err, auth.ErrOverwriteConfirmationRequired):
		return errx.ConfirmRequired("profile or credential replacement")
	case errors.Is(err, profile.ErrCorruptRegistry), errors.Is(err, profile.ErrInsecurePermissions), errors.Is(err, writepolicy.ErrCorruptRegistry), errors.Is(err, writepolicy.ErrInsecurePermissions):
		return errx.Internal("a local registry cannot be used safely")
	case errors.Is(err, writepolicy.ErrNotFound):
		return errx.NotFound("write_policy", name, nil)
	case errors.Is(err, writepolicy.ErrStale):
		return errx.Conflict("WRITE_POLICY_STALE", "the project policy does not match the current profile identity")
	case errors.Is(err, writepolicy.ErrProjectDenied):
		return errx.Permission("PROJECT_POLICY_DENIED", "the exact project ID and key are not allowlisted")
	case errors.Is(err, auth.ErrNotFound):
		return errx.Auth("CREDENTIAL_NOT_FOUND", "no stored credential exists for profile %q", name)
	case errors.Is(err, auth.ErrCredentialBindingMismatch):
		return errx.Auth("CREDENTIAL_BINDING_MISMATCH", "the stored credential does not match profile %q", name)
	case errors.Is(err, auth.ErrProfileChangedDuringLogin):
		return errx.Conflict("PROFILE_CHANGED_DURING_LOGIN", "profile %q changed while authentication was in progress", name)
	case errors.Is(err, auth.ErrUnsupported):
		return errx.Auth("KEYCHAIN_UNSUPPORTED", "this build has no supported native credential store")
	case errors.Is(err, auth.ErrInteractionNotAllowed):
		return errx.Auth("KEYCHAIN_INTERACTION_REQUIRED", "Keychain access requires an interactive operator session")
	case errors.Is(err, auth.ErrKeychainMigrationRequired):
		return errx.ConfirmRequired("Keychain ACL migration")
	case errors.Is(err, auth.ErrKeychainEntryNotFound):
		return errx.NotFound("keychain_credential", name, nil)
	case errors.Is(err, auth.ErrKeychainMigrationBlocked):
		return errx.Auth("KEYCHAIN_MIGRATION_BLOCKED", "Keychain ACL migration requires an interactive operator session")
	case errors.Is(err, auth.ErrKeychainMigrationCanceled):
		return errx.ConfirmRequired("Keychain ACL migration")
	case errors.Is(err, auth.ErrKeychainMigrationUnavailable):
		return errx.Auth("KEYCHAIN_MIGRATION_UNAVAILABLE", "Keychain ACL migration is unavailable in this build")
	case errors.Is(err, auth.ErrInvalidToken):
		return errx.Usage("credential input is invalid")
	case errors.Is(err, oauth.ErrInvalidCallback):
		return errx.Auth("OAUTH_CALLBACK_INVALID", "OAuth callback validation failed")
	case errors.Is(err, oauth.ErrAuthorizationDenied):
		return errx.Auth("OAUTH_AUTHORIZATION_DENIED", "YouTrack authorization was denied")
	case errors.Is(err, oauth.ErrTokenExchange):
		return errx.Auth("OAUTH_TOKEN_EXCHANGE_FAILED", "YouTrack OAuth token exchange failed")
	case errors.Is(err, oauth.ErrInvalidConfig):
		return errx.Usage("OAuth profile configuration is invalid")
	default:
		return errx.Internal("operation failed without exposing sensitive details")
	}
}

func profileInfo(value profile.Profile) ProfileInfo {
	capabilities := make([]string, len(value.Capabilities))
	for index, capability := range value.Capabilities {
		capabilities[index] = string(capability)
	}
	return ProfileInfo{Name: value.Name, Instance: value.ServiceURL, MCPURL: value.MCPURL, AccountID: value.ExpectedAccountID, Login: value.ExpectedLogin, Capabilities: capabilities, Executor: string(value.Executor), Assurance: string(value.Assurance)}
}

func policyProjects(values []ProjectRef) []writepolicy.Project {
	result := make([]writepolicy.Project, len(values))
	for index, value := range values {
		result[index] = writepolicy.Project{ID: value.ID, Key: value.Key}
	}
	return result
}

func projectRefs(values []writepolicy.Project) []ProjectRef {
	result := make([]ProjectRef, len(values))
	for index, value := range values {
		result[index] = ProjectRef{ID: value.ID, Key: value.Key}
	}
	return result
}

func policyInfo(value writepolicy.Policy) PolicyInfo {
	return PolicyInfo{Profile: value.Profile, IdentitySHA256: value.Identity, Revision: value.Revision, Projects: projectRefs(value.Projects)}
}

func userInfo(value youtrack.User) UserInfo {
	return UserInfo{ID: value.ID, Login: value.Login, Name: value.Name, FullName: value.FullName, Email: value.Email}
}

func projectInfo(value youtrack.Project) ProjectInfo {
	return ProjectInfo{ID: value.ID, Key: value.ShortName, Name: value.Name, Archived: value.Archived}
}

func issueInfo(value youtrack.Issue) IssueInfo {
	result := IssueInfo{ID: value.ID, ReadableID: value.IDReadable, Summary: value.Summary, Description: value.Description, Project: projectInfo(value.Project), Created: value.Created, Updated: value.Updated, CommentsCount: value.CommentsCount}
	if value.Reporter != nil {
		reporter := userInfo(*value.Reporter)
		result.Reporter = &reporter
	}
	result.CustomFields = make([]IssueCustomFieldInfo, len(value.CustomFields))
	for index, field := range value.CustomFields {
		result.CustomFields[index] = IssueCustomFieldInfo{ID: field.ID, Name: field.Name, Type: field.Type, Value: append(json.RawMessage(nil), field.Value...)}
	}
	return result
}

func projectFieldInfo(value youtrack.ProjectField) ProjectFieldInfo {
	result := ProjectFieldInfo{ID: value.ID, Name: value.Field.Name, Type: value.Type, ValueType: value.Field.FieldType.ValueType, IsMultiValue: value.Field.FieldType.IsMultiValue, CanBeEmpty: value.CanBeEmpty, IsPublic: value.IsPublic}
	if value.Bundle != nil {
		bundle := BundleInfo{ID: value.Bundle.ID, Type: value.Bundle.Type, Values: make([]BundleValueInfo, len(value.Bundle.Values)), AggregatedUsers: make([]UserInfo, len(value.Bundle.AggregatedUsers))}
		for index, item := range value.Bundle.Values {
			bundle.Values[index] = BundleValueInfo{ID: item.ID, Name: item.Name, Localized: item.Localized, Archived: item.Archived, Type: item.Type}
		}
		for index, user := range value.Bundle.AggregatedUsers {
			bundle.AggregatedUsers[index] = userInfo(user)
		}
		result.Bundle = &bundle
	}
	return result
}

func mutationInfo(value journal.Record, outputPath string) MutationInfo {
	return MutationInfo{PlanID: value.Plan.PlanID, State: string(value.State), Revision: value.Revision, Kind: string(value.Plan.Kind), Profile: value.Plan.Profile.Name, Instance: value.Plan.Profile.Instance, AccountID: value.Plan.Profile.Account.ID, AccountLogin: value.Plan.Profile.Account.Login, ProjectID: value.Plan.Policy.Project.ID, ProjectKey: value.Plan.Policy.Project.Key, IntentSHA256: value.Plan.IntentSHA256, RequestSHA256: value.Plan.RequestSHA256, ExpectedSHA256: value.Plan.ExpectedSHA256, MutationAttempts: value.MutationAttempts, NonReplayable: value.NonReplayable(), OutputPath: outputPath}
}

func skillResultInfo(values []skills.Result) []SkillResultInfo {
	result := make([]SkillResultInfo, len(values))
	for index, value := range values {
		files := make([]SkillFileInfo, len(value.Files))
		for fileIndex, file := range value.Files {
			files[fileIndex] = SkillFileInfo{Path: file.Path, Status: string(file.Status), Applied: file.Applied}
		}
		result[index] = SkillResultInfo{Provider: value.Provider, Scope: value.Scope, Root: value.Root, Skill: value.Skill, InSync: value.InSync, DryRun: value.DryRun, Files: files}
	}
	return result
}
