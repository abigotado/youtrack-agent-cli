package youtrack

import (
	"context"
	"net/url"
	"strconv"
	"strings"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
)

const (
	currentUserFields  = "id,login,name,fullName,email"
	projectFields      = "id,shortName,name,archived"
	issueFields        = "id,idReadable,summary,description,project(id,shortName,name,archived),reporter(id,login,name,fullName),created,updated,commentsCount,customFields(id,name,$type,value(id,name,login,fullName,text,presentation,isResolved,$type))"
	projectFieldFields = "id,$type,field(id,name,fieldType(id,valueType,isMultiValue,$type)),canBeEmpty,isPublic,bundle(id,$type,values(id,name,localizedName,archived,$type),aggregatedUsers(id,login,name,fullName))"
	commentFields      = "id,author(id,login,name,fullName),created,updated,deleted,text,visibility($type,permittedGroups(id,name),permittedUsers(id,name,login))"
)

// CurrentUser reads the authenticated account identity.
func (client *Client) CurrentUser(ctx context.Context) (User, error) {
	var user User
	err := client.readJSON(ctx, request{
		path: "/users/me", query: fieldsQuery(currentUserFields), operation: "users.me",
	}, &user)
	if err != nil {
		return User{}, err
	}
	if !validEntityID(user.ID) || strings.TrimSpace(user.Login) == "" {
		return User{}, invalidReadResponse()
	}
	return user, nil
}

// GetProject reads one project by exact entity ID or exact short name.
func (client *Client) GetProject(ctx context.Context, projectID string) (Project, error) {
	if err := validateIdentifier("project", projectID); err != nil {
		return Project{}, err
	}
	var project Project
	err := client.readJSON(ctx, request{
		path: "/admin/projects/" + url.PathEscape(projectID), query: fieldsQuery(projectFields), operation: "projects.get",
	}, &project)
	if err != nil {
		return Project{}, err
	}
	if !validEntityID(project.ID) || project.ShortName == "" || (project.ID != projectID && project.ShortName != projectID) {
		return Project{}, invalidReadResponse()
	}
	return project, nil
}

// GetIssue reads one issue by exact database ID or exact readable ID.
func (client *Client) GetIssue(ctx context.Context, issueID string) (Issue, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return Issue{}, err
	}
	var issue Issue
	err := client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID), query: fieldsQuery(issueFields), operation: "issues.get",
	}, &issue)
	if err != nil {
		return Issue{}, err
	}
	if err := validateIssueResponse(issue, issueID); err != nil {
		return Issue{}, err
	}
	return issue, nil
}

// ListProjectFields reads exactly one bounded page of project field schemas.
// Nested bundle values are additionally bounded by the global response limit.
func (client *Client) ListProjectFields(ctx context.Context, projectID string, options PageOptions) ([]ProjectField, error) {
	if err := validateIdentifier("project", projectID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, projectFieldFields)
	if err != nil {
		return nil, err
	}
	var fields []ProjectField
	err = client.readJSON(ctx, request{
		path: "/admin/projects/" + url.PathEscape(projectID) + "/customFields", query: query, operation: "project_fields.list", pageReducible: options.CanReduce,
	}, &fields)
	if err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, invalidReadResponse()
	}
	for _, field := range fields {
		if !validEntityID(field.ID) || !validEntityID(field.Field.ID) || field.Field.Name == "" || field.Type == "" {
			return nil, invalidReadResponse()
		}
	}
	return fields, nil
}

// ListComments reads exactly one bounded page. The API documents no ordering,
// author, or time filter, so callers must not infer those server guarantees.
func (client *Client) ListComments(ctx context.Context, issueID string, options PageOptions) ([]Comment, error) {
	if err := validateIdentifier("issue", issueID); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, commentFields)
	if err != nil {
		return nil, err
	}
	var comments []Comment
	err = client.readJSON(ctx, request{
		path: "/issues/" + url.PathEscape(issueID) + "/comments", query: query, operation: "comments.list", pageReducible: options.CanReduce,
	}, &comments)
	if err != nil {
		return nil, err
	}
	if comments == nil {
		return nil, invalidReadResponse()
	}
	for _, comment := range comments {
		if !validEntityID(comment.ID) {
			return nil, invalidReadResponse()
		}
	}
	return comments, nil
}

// SearchIssues runs one bounded YouTrack issue query and never fetches a
// second page. It exists for reconciliation, not open-ended agent discovery.
func (client *Client) SearchIssues(ctx context.Context, queryText string, options PageOptions) ([]Issue, error) {
	if err := validateBoundedQuery(queryText); err != nil {
		return nil, err
	}
	query, err := pageQuery(options, issueFields)
	if err != nil {
		return nil, err
	}
	query.Set("query", queryText)
	var issues []Issue
	if err := client.readJSON(ctx, request{path: "/issues", query: query, operation: "issues.search", pageReducible: options.CanReduce}, &issues); err != nil {
		return nil, err
	}
	if issues == nil {
		return nil, invalidReadResponse()
	}
	for _, issue := range issues {
		if err := validateIssueResponse(issue, ""); err != nil {
			return nil, err
		}
	}
	return issues, nil
}

func fieldsQuery(fields string) url.Values {
	query := url.Values{}
	query.Set("fields", fields)
	return query
}

func pageQuery(options PageOptions, fields string) (url.Values, error) {
	if options.Top == 0 {
		options.Top = defaultCollectionLimit
	}
	if options.Top < 1 || options.Top > maxCollectionPageSize {
		return nil, errx.Usage("top must be between 1 and %d", maxCollectionPageSize)
	}
	if options.Skip < 0 {
		return nil, errx.Usage("skip must not be negative")
	}
	query := fieldsQuery(fields)
	query.Set("$top", strconv.Itoa(options.Top))
	query.Set("$skip", strconv.Itoa(options.Skip))
	return query, nil
}

func validateIdentifier(kind, value string) error {
	if validEntityID(value) {
		return nil
	}
	return errx.Usage("%s identifier must be 1-%d ASCII letters, digits, dot, dash, or underscore", kind, maxIdentifierBytes)
}

func validEntityID(value string) bool {
	if value == "" || len(value) > maxIdentifierBytes {
		return false
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validateBoundedQuery(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxQueryBytes || strings.ContainsAny(value, "\x00\r\n") {
		return errx.Usage("query must be one non-empty line no longer than %d bytes", maxQueryBytes)
	}
	return nil
}

func validateIssueResponse(issue Issue, requestedID string) error {
	if !validEntityID(issue.ID) || !validEntityID(issue.IDReadable) || issue.Summary == "" ||
		!validEntityID(issue.Project.ID) || issue.Project.ShortName == "" || issue.CommentsCount < 0 {
		return invalidReadResponse()
	}
	if requestedID != "" && issue.ID != requestedID && issue.IDReadable != requestedID {
		return invalidReadResponse()
	}
	for _, field := range issue.CustomFields {
		if !validEntityID(field.ID) || field.Name == "" || field.Type == "" || len(field.Value) > maxCustomFieldValueSize {
			return invalidReadResponse()
		}
	}
	return nil
}
