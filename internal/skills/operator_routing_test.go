//go:build !portable_readonly && !macos_identity_readonly

package skills

import (
	"strings"
	"testing"
)

func TestStandardSkillDistinguishesOperatorConsentFromNativeReceipt(t *testing.T) {
	for _, provider := range []Provider{ProviderCodex, ProviderClaude} {
		t.Run(string(provider), func(t *testing.T) {
			files, err := payload(provider)
			if err != nil {
				t.Fatal(err)
			}
			policy := strings.Join(strings.Fields(string(files["reference/write-policy.md"])), " ")
			for _, required := range []string{
				"capabilities --profile NAME -o json",
				"not proof of live credentials or server permissions",
				"request a released upgrade, not an unavailable receipt",
				"full final comment including marker",
				"--kind issue.create --project KEY",
				"full final description including marker",
				"PROJECT_POLICY_DENIED",
				"remote_readable_id",
				"not permission to develop the feature",
				"--confirm-intent SHA256 --yes",
				"cryptographic human presence",
				"WRITE_OUTCOME_UNKNOWN",
				"WRITE_APPLIED_LOCAL_FAILURE",
				"Reconciliation never restores plan eligibility",
				"Operator confirmation does not unlock it or mint its receipt",
			} {
				if !strings.Contains(policy, required) {
					t.Errorf("operator policy lacks %q", required)
				}
			}
		})
	}
}
