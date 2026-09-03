package arch_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
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
	Deps       []string
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

func imports(names ...string) map[string]bool {
	result := make(map[string]bool, len(names))
	for _, name := range names {
		result[name] = true
	}
	return result
}

func TestInternalDependencyDAGIsExplicit(t *testing.T) {
	allowed := map[string]map[string]bool{
		module + "/internal/application":   edges("approval", "auth", "endpoint", "errx", "intent", "journal", "mutation", "oauth", "profile", "skills", "writepolicy", "youtrack"),
		module + "/internal/approval":      edges("errx", "intent", "protocolvalue"),
		module + "/internal/arch":          {},
		module + "/internal/auth":          edges("profile"),
		module + "/internal/cli":           edges("application", "errx", "output"),
		module + "/internal/endpoint":      edges("protocolvalue"),
		module + "/internal/errx":          {},
		module + "/internal/intent":        edges("endpoint", "protocolvalue"),
		module + "/internal/journal":       edges("errx", "intent", "lockfile"),
		module + "/internal/lockfile":      {},
		module + "/internal/mutation":      edges("errx", "intent"),
		module + "/internal/oauth":         edges("endpoint"),
		module + "/internal/output":        edges("errx"),
		module + "/internal/profile":       edges("endpoint", "lockfile"),
		module + "/internal/protocolvalue": {},
		module + "/internal/skills":        edges("errx", "lockfile"),
		module + "/internal/writepolicy":   edges("lockfile", "profile"),
		module + "/internal/youtrack":      edges("errx"),
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

func TestApprovalProtocolHasNoProductionTransportImports(t *testing.T) {
	allowedInternal := edges("approval", "endpoint", "errx", "intent", "protocolvalue")
	allowedDirect := map[string]map[string]bool{
		module + "/internal/approval": imports(
			"bytes", "context", "crypto/ecdsa", "crypto/elliptic", "crypto/rand", "crypto/sha256", "crypto/subtle",
			"encoding/asn1", "encoding/base64", "encoding/binary", "encoding/hex", "encoding/json", "fmt", "io", "math/big", "time",
			module+"/internal/errx", module+"/internal/intent", module+"/internal/protocolvalue",
		),
		module + "/internal/endpoint": imports(
			"errors", "fmt", "net", "net/url", "sort", "strconv", "strings", module+"/internal/protocolvalue",
		),
		module + "/internal/errx": imports("context", "errors", "fmt", "strings", "time"),
		module + "/internal/intent": imports(
			"bytes", "crypto/rand", "crypto/sha256", "encoding/base32", "encoding/hex", "encoding/json", "errors", "fmt", "io", "regexp", "sort", "strings", "unicode/utf8",
			module+"/internal/endpoint", module+"/internal/protocolvalue",
		),
		module + "/internal/protocolvalue": imports(
			"crypto/sha256", "encoding/base32", "encoding/hex", "errors", "fmt", "strconv", "strings",
		),
	}
	allPackages := listedPackages(t, "./internal/...")
	byPath := make(map[string]packageInfo, len(allPackages))
	for _, value := range allPackages {
		byPath[value.ImportPath] = value
	}
	root := byPath[module+"/internal/approval"]
	reachable := map[string]bool{root.ImportPath: true}
	for _, dependency := range root.Deps {
		if strings.HasPrefix(dependency, module+"/internal/") {
			reachable[dependency] = true
			if !allowedInternal[dependency] {
				t.Errorf("approval value protocol transitively imports unapproved internal package %s", dependency)
			}
		}
	}
	for packagePath := range reachable {
		_, ok := byPath[packagePath]
		if !ok {
			t.Errorf("approval dependency %s was not listed", packagePath)
			continue
		}
		allowed, ok := allowedDirect[packagePath]
		if !ok {
			t.Errorf("approval dependency %s has no direct-import allowlist", packagePath)
			continue
		}
		for _, imported := range allGoImports(t, packagePath) {
			if !allowed[imported] {
				t.Errorf("approval dependency %s directly imports unapproved package %s", packagePath, imported)
			}
		}
	}
	assertEndpointNetworkSelectors(t)
}

func allGoImports(t *testing.T, packagePath string) []string {
	t.Helper()
	relative := strings.TrimPrefix(packagePath, module+"/")
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), relative, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			seen[strings.Trim(spec.Path.Value, `"`)] = true
		}
	}
	result := make([]string, 0, len(seen))
	for imported := range seen {
		result = append(result, imported)
	}
	sort.Strings(result)
	return result
}

func assertEndpointNetworkSelectors(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), "internal", "endpoint", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]map[string]bool{
		"net": {"ParseIP": true},
		"url": {"Parse": true, "ParseQuery": true, "URL": true},
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		aliases := map[string]string{}
		for _, spec := range file.Imports {
			importPath := strings.Trim(spec.Path.Value, `"`)
			if importPath != "net" && importPath != "net/url" {
				continue
			}
			alias := filepath.Base(importPath)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias == "." || alias == "_" {
				t.Errorf("endpoint uses uninspectable %s import alias %q", importPath, alias)
				continue
			}
			aliases[alias] = filepath.Base(importPath)
		}
		file, err = parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			packageName, ok := aliases[identifier.Name]
			if ok && !allowed[packageName][selector.Sel.Name] {
				t.Errorf("endpoint uses unapproved %s selector %s in %s", packageName, selector.Sel.Name, filepath.Base(path))
			}
			return true
		})
	}
}

func TestNativeApprovalProtocolImportsArePinned(t *testing.T) {
	root := filepath.Join(repositoryRoot(t), "native", "macos", "ApprovalProtocol", "Sources", "ApprovalProtocol")
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.Mode().IsRegular() && strings.HasSuffix(path, ".swift") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("native approval protocol target contains no Swift sources")
	}
	sort.Strings(files)
	allowed := map[string]bool{"CryptoKit": true, "Foundation": true}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, moduleName := range swiftImportedModules(string(raw)) {
			if !allowed[moduleName] {
				t.Errorf("native approval protocol imports unapproved module %s in %s", moduleName, filepath.Base(path))
			}
		}
	}
}

func TestSwiftImportScannerCoversAttributedAccessLevelBOMAndScopedForms(t *testing.T) {
	raw := "\ufeff@preconcurrency import Network\n" +
		"@_implementationOnly import AppKit\n" +
		"internal import Observation\n" +
		"public import struct CryptoKit.SHA256\n" +
		"import Foundation; import LocalAuthentication // trailing comment\n"
	want := []string{"AppKit", "CryptoKit", "Foundation", "LocalAuthentication", "Network", "Observation"}
	got := swiftImportedModules(raw)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Swift import modules = %v, want %v", got, want)
	}
}

func swiftImportedModules(raw string) []string {
	raw = strings.TrimPrefix(raw, "\ufeff")
	importKinds := map[string]bool{
		"class": true, "enum": true, "func": true, "let": true, "protocol": true,
		"struct": true, "typealias": true, "var": true,
	}
	var result []string
	for _, line := range strings.Split(raw, "\n") {
		line, _, _ = strings.Cut(line, "//")
		for _, statement := range strings.Split(line, ";") {
			fields := strings.Fields(statement)
			for index, field := range fields {
				if field != "import" {
					continue
				}
				moduleIndex := index + 1
				if moduleIndex < len(fields) && importKinds[fields[moduleIndex]] {
					moduleIndex++
				}
				if moduleIndex >= len(fields) {
					result = append(result, "<malformed-import>")
					break
				}
				moduleName := strings.SplitN(fields[moduleIndex], ".", 2)[0]
				result = append(result, strings.TrimSpace(moduleName))
				break
			}
		}
	}
	return result
}
