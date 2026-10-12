//go:build !portable_readonly && !macos_identity_readonly

package skills

import (
	"strings"
	"testing"
)

func TestStandardSkillRoutesUnavailableMCPCommentsToBoundedCLI(t *testing.T) {
	for _, provider := range []Provider{ProviderCodex, ProviderClaude} {
		t.Run(string(provider), func(t *testing.T) {
			files, err := payload(provider)
			if err != nil {
				t.Fatal(err)
			}
			for _, contract := range []struct {
				file     string
				required []string
			}{
				{"SKILL.md", []string{"If MCP comments are unavailable, use the standard CLI's exact, bounded comments fallback", "[read policy](reference/read-policy.md)"}},
				{"reference/read-policy.md", []string{"If `get_issue_comments` is unavailable", "youtrack-agent-cli inspect comments --profile <name> --id <issue-ID> --limit 10 --offset 0 -o json"}},
			} {
				text := strings.Join(strings.Fields(string(files[contract.file])), " ")
				for _, required := range contract.required {
					if !strings.Contains(text, required) {
						t.Errorf("%s misses comments routing %q", contract.file, required)
					}
				}
			}
		})
	}
}
