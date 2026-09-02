package arch_test

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const module = "github.com/abigotado/youtrack-agent-cli"

type packageInfo struct {
	ImportPath string
	Imports    []string
}

func listedPackages(t *testing.T, pattern string) []packageInfo {
	t.Helper()
	command := exec.Command("go", "list", "-json", pattern)
	command.Dir = repositoryRoot(t)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(stdout)
	var result []packageInfo
	for {
		var value packageInfo
		err := decoder.Decode(&value)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decode go list: %v", err)
		}
		result = append(result, value)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("go list %s: %v", pattern, err)
	}
	return result
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("repository root not found")
		}
		directory = parent
	}
}

func edges(names ...string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[module+"/internal/"+name] = true
	}
	return result
}

func TestInternalDependencyDAGIsExplicit(t *testing.T) {
	allowed := map[string]map[string]bool{
		module + "/internal/application": edges("approval", "auth", "endpoint", "errx", "intent", "journal", "mutation", "oauth", "profile", "skills", "writepolicy", "youtrack"),
		module + "/internal/approval":    edges("errx", "intent"),
		module + "/internal/arch":        {},
		module + "/internal/auth":        edges("profile"),
		module + "/internal/cli":         edges("application", "errx", "output"),
		module + "/internal/endpoint":    {},
		module + "/internal/errx":        {},
		module + "/internal/intent":      {},
		module + "/internal/journal":     edges("errx", "intent", "lockfile"),
		module + "/internal/lockfile":    {},
		module + "/internal/mutation":    edges("errx", "intent"),
		module + "/internal/oauth":       edges("endpoint"),
		module + "/internal/output":      edges("errx"),
		module + "/internal/profile":     edges("endpoint", "lockfile"),
		module + "/internal/skills":      edges("errx", "lockfile"),
		module + "/internal/writepolicy": edges("lockfile", "profile"),
		module + "/internal/youtrack":    edges("errx"),
	}

	packages := listedPackages(t, "./internal/...")
	for _, value := range packages {
		permitted, known := allowed[value.ImportPath]
		if !known {
			t.Errorf("internal package %s has no explicit DAG entry", value.ImportPath)
			continue
		}
		for _, imported := range value.Imports {
			if strings.HasPrefix(imported, module+"/internal/") && !permitted[imported] {
				t.Errorf("unlisted dependency edge %s -> %s", value.ImportPath, imported)
			}
		}
	}
	if len(packages) != len(allowed) {
		names := make([]string, 0, len(packages))
		for _, value := range packages {
			names = append(names, value.ImportPath)
		}
		sort.Strings(names)
		t.Fatalf("DAG inventory has %d entries for %d packages: %s", len(allowed), len(packages), strings.Join(names, ", "))
	}
}

func TestProcessEntryImportsOnlyCLIAndContract(t *testing.T) {
	allowed := map[string]bool{
		module + "/internal/cli":    true,
		module + "/internal/errx":   true,
		module + "/internal/output": true,
	}
	packages := listedPackages(t, "./cmd/youtrack-agent-cli")
	if len(packages) != 1 {
		t.Fatalf("listed %d command packages", len(packages))
	}
	for _, imported := range packages[0].Imports {
		if strings.HasPrefix(imported, module+"/internal/") && !allowed[imported] {
			t.Errorf("process entry bypasses CLI/application boundary through %s", imported)
		}
	}
}

func TestCLIDoesNotImportNetHTTP(t *testing.T) {
	packages := listedPackages(t, "./internal/cli")
	for _, imported := range packages[0].Imports {
		if imported == "net/http" {
			t.Fatal("internal/cli imports net/http")
		}
	}
}
