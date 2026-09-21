#!/usr/bin/env ruby

require "pathname"
require "yaml"

ALLOWED_ACTIONS = %w[actions/checkout actions/setup-go actions/setup-python].freeze
READONLY_TAG = "portable_readonly"
FORBIDDEN_PACKAGES = %r{/internal/(?:auth|application|journal|mutation|youtrack)$}.freeze
CHECKOUT_STEP = {
  "name" => "Git checkout",
  "uses" => "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "with" => { "fetch-depth" => 0, "persist-credentials" => false },
}.freeze
SETUP_GO_STEP = {
  "name" => "Set up Go",
  "uses" => "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
  "with" => { "go-version-file" => "go.mod", "cache" => true },
}.freeze
VERIFY_TAG_RUN = <<~SH
  set -euo pipefail
  test "${GITHUB_REF_TYPE}" = tag
  printf '%s' "${GITHUB_REF_NAME}" | grep -Eq '^v0\\.[0-9]+\\.[0-9]+$'
  release_commit="$(git rev-parse "${GITHUB_SHA}^{commit}")"
  git fetch origin main:refs/remotes/origin/main
  git merge-base --is-ancestor "${release_commit}" origin/main
  git tag --points-at "${release_commit}" | grep -Fxq "${GITHUB_REF_NAME}"
SH
VERIFY_BOUNDARY_RUN = <<~SH
  set -euo pipefail
  go test -race ./...
  go test -tags portable_readonly ./...
  test -z "$(go list -tags portable_readonly -deps ./cmd/youtrack-agent-cli | grep -E '/internal/(auth|application|journal|mutation|youtrack)$' || true)"
  go build -tags portable_readonly -o portable-readonly ./cmd/youtrack-agent-cli
  ./portable-readonly --help | grep -Fxq '  profile     Manage non-secret read-only Remote MCP profiles'
  ! ./portable-readonly --help | grep -Eiq 'auth|inspect|mutation'
SH
VERIFY_POLICY_RUN = <<~SH
  set -euo pipefail
  go install github.com/goreleaser/goreleaser/v2@v2.17.1
  goreleaser check
  ruby .github/scripts/verify-portable-release-policy_test.rb
  ruby .github/scripts/verify-portable-release-policy.rb .goreleaser.yaml
SH
EXPECTED_RELEASE_WORKFLOW = {
  "name" => "release-portable-readonly",
  true => { "push" => { "tags" => ["v0.*"] } },
  "permissions" => { "contents" => "read" },
  "jobs" => {
    "verify-portable-readonly" => {
      "name" => "Verify portable Remote-MCP read-only release", "runs-on" => "ubuntu-latest",
      "steps" => [
        CHECKOUT_STEP, SETUP_GO_STEP,
        { "name" => "Verify release tag is on main", "run" => VERIFY_TAG_RUN },
        { "name" => "Verify portable read-only boundary", "run" => VERIFY_BOUNDARY_RUN },
        { "name" => "Verify release policy and config", "env" => { "GOTOOLCHAIN" => "auto" }, "run" => VERIFY_POLICY_RUN },
      ],
    },
    "publish-portable-readonly" => {
      "name" => "Publish checksummed portable read-only archives", "needs" => "verify-portable-readonly",
      "permissions" => { "contents" => "write" }, "runs-on" => "ubuntu-latest",
      "steps" => [
        CHECKOUT_STEP, SETUP_GO_STEP,
        { "name" => "Reverify release tag is on main", "run" => VERIFY_TAG_RUN },
        { "name" => "Install pinned GoReleaser", "env" => { "GOTOOLCHAIN" => "auto" }, "run" => "go install github.com/goreleaser/goreleaser/v2@v2.17.1" },
        { "name" => "Publish checksummed portable read-only archives", "env" => { "GITHUB_TOKEN" => "${{ github.token }}" }, "run" => "goreleaser release --clean --config .goreleaser.yaml" },
      ],
    },
  },
}.freeze

path = ARGV.fetch(0) do
  warn "usage: verify-portable-release-policy.rb GORELEASER_CONFIG [REPOSITORY_ROOT]"
  exit 2
end
root = File.expand_path(ARGV.fetch(1, File.dirname(File.expand_path(path))))

begin
  config = YAML.safe_load(File.read(path), permitted_classes: [], aliases: false)
rescue Errno::ENOENT, Psych::Exception => error
  warn "portable read-only release policy: cannot read config: #{error.message}"
  exit 1
end

errors = []
unless config.is_a?(Hash) && config["version"] == 2 && config["project_name"] == "youtrack-agent-cli"
  errors << "release config must identify the v2 youtrack-agent-cli project"
end
errors << "release config contains an unapproved top-level section" unless (config.keys - %w[version project_name builds archives checksum release]).empty?

builds = config.fetch("builds", [])
unless builds.length == 1
  errors << "release config must contain exactly one portable read-only build"
else
  build = builds.first
  expected = {
    "id" => "portable-readonly", "main" => "./cmd/youtrack-agent-cli", "binary" => "youtrack-agent-cli",
    "tags" => [READONLY_TAG], "env" => ["CGO_ENABLED=0"], "flags" => ["-trimpath"],
    "goos" => ["linux"], "goarch" => %w[amd64 arm64],
  }
  expected.each { |key, value| errors << "portable build has invalid #{key}" unless build[key] == value }
  errors << "portable build contains an unapproved setting" unless (build.keys - (expected.keys + ["ldflags"])).empty?
  expected_ldflags = [
    "-s -w",
    "-X github.com/abigotado/youtrack-agent-cli/internal/readonlycli.releaseVersion={{ .Version }}",
    "-X github.com/abigotado/youtrack-agent-cli/internal/readonlycli.releaseCommit={{ .FullCommit }}",
    "-X github.com/abigotado/youtrack-agent-cli/internal/readonlycli.releaseCommitTime={{ .CommitDate }}",
  ]
  errors << "portable build has invalid provenance ldflags" unless build["ldflags"] == expected_ldflags
end

archives = config.fetch("archives", [])
expected_archive = {
  "id" => "portable-readonly", "ids" => ["portable-readonly"], "formats" => ["tar.gz"],
  "name_template" => "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}",
}
unless archives == [expected_archive]
  errors << "release config must publish only portable read-only tar.gz archives"
end
errors << "release config must publish only the approved checksum" unless config["checksum"] == { "name_template" => "checksums.txt" }
unless config["release"] == { "github" => { "owner" => "abigotado", "name" => "youtrack-agent-cli" } }
  errors << "release config must target only the canonical GitHub repository"
end
%w[homebrew homebrew_casks nfpms docks brews blobs uploads universal_binaries].each do |key|
  errors << "portable release config must not define #{key}" if config.key?(key)
end

Dir.glob(File.join(root, "{Formula,Cask,Casks}/**/*.rb"), File::FNM_EXTGLOB).each do |candidate|
  errors << "Homebrew Formula/Cask is forbidden: #{Pathname.new(candidate).relative_path_from(Pathname.new(root))}"
end

surface = [File.join(root, ".github/workflows/**/*"), File.join(root, "packaging/**/*"), File.join(root, "scripts/**/*")].flat_map { |glob| Dir.glob(glob) }.uniq
surface.each do |candidate|
  next unless File.file?(candidate)
  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  next if relative == ".github/workflows/release.yaml"
  content = File.binread(candidate).force_encoding(Encoding::UTF_8).scrub
  errors << "#{relative} contains a Homebrew or quarantine bypass" if content.match?(/(?:\bbrew\s+(?:tap|tap-new|create|bump)|\bxattr\b|com\.apple\.quarantine|spctl\s+--master-disable)/i)
  errors << "#{relative} contains a publication action" if content.match?(/(?:\bgoreleaser\s+release\b|\bgh\s+(?:api|release)\b|action-gh-release|\/upload-artifact@)/i)
end

workflows = Dir.glob(File.join(root, ".github/workflows/*.{yaml,yml}"))
workflows.each do |candidate|
  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  begin
    workflow = YAML.safe_load(File.read(candidate), permitted_classes: [], aliases: false)
  rescue Psych::Exception => error
    errors << "#{relative} is invalid YAML: #{error.message}"
    next
  end
  unless workflow.is_a?(Hash)
    errors << "#{relative} must be a mapping"
    next
  end
  release = relative == ".github/workflows/release.yaml"
  permissions = workflow["permissions"]
  if release
    errors << "release workflow must equal the approved portable read-only publisher" unless workflow == EXPECTED_RELEASE_WORKFLOW
  else
    errors << "#{relative} must set read-only permissions" unless permissions == { "contents" => "read" }
  end
  walk = lambda do |value, nested_permissions = false|
    case value
    when Hash
      value.each do |key, item|
        if key.to_s == "permissions" && nested_permissions
          errors << "#{relative} has nested workflow permissions"
        end
        if key.to_s == "uses"
          action, revision = item.to_s.split("@", 2)
          errors << "#{relative} uses unapproved action #{action.inspect}" unless ALLOWED_ACTIONS.include?(action)
          errors << "#{relative} uses an unpinned action" unless revision&.match?(/\A[0-9a-f]{40}\z/)
        end
        walk.call(item, nested_permissions || key.to_s == "jobs")
      end
    when Array
      value.each { |item| walk.call(item, nested_permissions) }
    when String
      errors << "#{relative} references forbidden secrets context" if value.match?(/\$\{\{.*\bsecrets\b/im)
    end
  end
  walk.call(workflow) unless release
end

if errors.empty?
  puts "portable read-only release policy ok"
  exit 0
end
errors.each { |error| warn "portable read-only release policy: #{error}" }
exit 1
