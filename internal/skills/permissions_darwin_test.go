//go:build darwin && cgo

package skills

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

func TestExtendedACLDestinationIsRefusedForInstallAndUninstall(t *testing.T) {
	current, err := user.Current()
	if err != nil || current.Username == "" {
		t.Fatalf("resolve current macOS user: %v", err)
	}

	installDestination := t.TempDir()
	addExtendedACL(t, installDestination, current.Username)
	if _, err := Install(context.Background(), Options{
		Provider:  ProviderClaude,
		Scope:     ScopeUser,
		Dest:      installDestination,
		Confirmed: true,
	}); err == nil {
		t.Fatal("install accepted a destination with an extended ACL")
	} else {
		assertReason(t, err, "DEST_SHARED_WRITABLE")
	}
	if _, err := os.Stat(filepath.Join(installDestination, SkillName)); !os.IsNotExist(err) {
		t.Fatalf("install created a skill directory after ACL refusal: %v", err)
	}

	uninstallDestination := t.TempDir()
	opts := Options{
		Provider:  ProviderClaude,
		Scope:     ScopeUser,
		Dest:      uninstallDestination,
		Confirmed: true,
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("seed installed skill: %v", err)
	}
	addExtendedACL(t, uninstallDestination, current.Username)
	if _, err := Uninstall(context.Background(), opts); err == nil {
		t.Fatal("uninstall accepted a destination with an extended ACL")
	} else {
		assertReason(t, err, "DEST_SHARED_WRITABLE")
	}
	if _, err := os.Stat(filepath.Join(uninstallDestination, SkillName)); err != nil {
		t.Fatalf("uninstall changed the skill directory after ACL refusal: %v", err)
	}
}

func addExtendedACL(t *testing.T, target, username string) {
	t.Helper()
	command := exec.Command("/bin/chmod", "+a", "user:"+username+" allow read", target)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("add extended ACL to %s: %v (%s)", target, err, output)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("stat ACL-bearing destination: %v", err)
	}
	if !isSharedWritable(target, info) {
		t.Fatal("extended ACL was not detected as unsafe")
	}
}
