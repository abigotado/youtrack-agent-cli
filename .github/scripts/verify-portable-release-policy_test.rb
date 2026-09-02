#!/usr/bin/env ruby

require "minitest/autorun"
require "fileutils"
require "open3"
require "tmpdir"
require "yaml"

class VerifyDisabledReleasePolicyTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  VERIFIER = File.join(__dir__, "verify-portable-release-policy.rb")
  CONFIG = YAML.safe_load(File.read(File.join(ROOT, ".goreleaser.yaml")), permitted_classes: [], aliases: false)
  RELEASE_WORKFLOW = File.read(File.join(ROOT, ".github/workflows/release.yaml"))
  RELEASE_WORKFLOW_CONFIG = YAML.safe_load(RELEASE_WORKFLOW, permitted_classes: [], aliases: false)
  GO_WORKFLOW = File.read(File.join(ROOT, ".github/workflows/go.yaml"))
  GO_WORKFLOW_CONFIG = YAML.safe_load(GO_WORKFLOW, permitted_classes: [], aliases: false)

  def verify(config, files = {})
    Dir.mktmpdir("disabled-release-policy") do |root|
      config_path = File.join(root, ".goreleaser.yaml")
      File.write(config_path, YAML.dump(config))
      files.each do |relative, content|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        File.write(target, content)
      end
      _stdout, stderr, status = Open3.capture3("ruby", VERIFIER, config_path, root)
      return [status.success?, stderr]
    end
  end

  def test_current_configuration_passes
    success, stderr = verify(CONFIG)
    assert success, stderr
  end

  def test_only_build_is_skipped
    assert_equal [{ "id" => "distribution-disabled", "skip" => true }], CONFIG.fetch("builds")
    refute CONFIG.key?("archives")
    refute CONFIG.key?("release")
  end

  def test_rejects_any_enabled_build
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").first["skip"] = false
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "fail-closed sentinel"
  end

  def test_rejects_any_distribution_section
    %w[archives checksum release uploads homebrew_casks universal_binaries].each do |section|
      changed = Marshal.load(Marshal.dump(CONFIG))
      changed[section] = []
      success, stderr = verify(changed)
      refute success, section
      assert_includes stderr, "fail-closed sentinel"
    end
  end

  def test_rejects_a_quarantine_bypass
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed["hooks"] = { "post" => "/usr/bin/xattr -dr com.apple.quarantine youtrack-agent-cli" }
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "Gatekeeper quarantine bypass"
  end

  def test_allows_non_executable_homebrew_readiness_material
    success, stderr = verify(
      CONFIG,
      {
        "docs/homebrew.md" => "Example only: class YoutrackAgentCli < Formula; never publish it.\n",
        "packaging/homebrew/dependencies.json" => "{\"schema_version\":1}\n",
        "tools/homebrewcheck/main.go" => "package main // offline readiness checker\n",
      },
    )
    assert success, stderr
  end

  def test_scans_executable_homebrew_readiness_tools
    payloads = {
      "publication credential" => "package main // HOMEBREW_TAP_TOKEN\n",
      "Homebrew tap write" => "package main // brew bump-formula-pr abigotado/tap/youtrack-agent-cli\n",
      "release or upload action" => "package main // goreleaser release --clean\n",
      "Gatekeeper quarantine bypass" => "package main // xattr -dr com.apple.quarantine binary\n",
    }
    payloads.each do |finding, payload|
      success, stderr = verify(CONFIG, "tools/homebrewcheck/publish.go" => payload)
      refute success, finding
      assert_includes stderr, finding
    end
  end

  def test_rejects_formula_and_cask_paths
    [
      "Formula/youtrack-agent-cli.rb",
      "Cask/youtrack-agent-cli.rb",
      "Casks/youtrack-agent-cli.rb",
    ].each do |relative|
      success, stderr = verify(CONFIG, relative => "# active package\n")
      refute success, relative
      assert_includes stderr, "active Homebrew Formula/Cask"
    end
  end

  def test_rejects_formula_source_outside_conventional_directory
    source = <<~RUBY
      class YoutrackAgentCli < Formula
      end
    RUBY
    success, stderr = verify(CONFIG, "packaging/homebrew.rb" => source)
    refute success
    assert_includes stderr, "active Homebrew Formula/Cask"
  end

  def test_rejects_ruby_packaging_at_every_nested_path
    ["homebrew/youtrack-agent-cli.rb", "dist/formula.rb", "nested/release/tool.rb"].each do |relative|
      success, stderr = verify(CONFIG, relative => "# packaging entry point\n")
      refute success, relative
      assert_includes stderr, "Ruby packaging/release file is forbidden"
    end
  end

  def test_rejects_tap_credentials_and_writes
    workflow = <<~YAML
      permissions:
        contents: write
      jobs:
        publish:
          steps:
            - run: brew tap abigotado/tap && git push origin HEAD
              env:
                HOMEBREW_TAP_GITHUB_TOKEN: ${{ secrets.TAP_TOKEN }}
    YAML
    success, stderr = verify(CONFIG, ".github/workflows/homebrew.yaml" => workflow)
    refute success
    assert_includes stderr, "publication credential reference"
    assert_includes stderr, "Homebrew tap write"
    assert_includes stderr, "publication write permission"
  end

  def test_rejects_workflow_permission_bypass_forms
    workflows = {
      "write-all" => "permissions: write-all\njobs: {}\n",
      "flow mapping" => "permissions: { contents: write }\njobs: {}\n",
      "job level quoted" => <<~YAML,
        permissions:
          contents: read
        jobs:
          publish:
            permissions: { "packages": "write" }
            runs-on: ubuntu-latest
            steps: []
      YAML
      "missing top-level" => "jobs: {}\n",
    }
    workflows.each do |name, workflow|
      success, stderr = verify(CONFIG, ".github/workflows/#{name.tr(" ", "-")}.yaml" => workflow)
      refute success, name
      assert_match(/permission/, stderr, name)
    end
  end

  def test_rejects_unapproved_or_unpinned_workflow_actions
    workflows = {
      "unknown" => "evil/release@0123456789012345678901234567890123456789",
      "unpinned" => "actions/checkout@v7",
    }
    workflows.each do |name, action|
      workflow = <<~YAML
        permissions:
          contents: read
        jobs:
          check:
            runs-on: ubuntu-latest
            steps:
              - uses: #{action}
      YAML
      success, stderr = verify(CONFIG, ".github/workflows/#{name}.yaml" => workflow)
      refute success, name
      assert_match(/unapproved workflow action|not pinned to a commit SHA/, stderr, name)
    end
  end

  def test_allows_closed_read_only_workflow_policy
    workflow = <<~YAML
      permissions: read-all
      jobs:
        check:
          permissions:
            contents: read
          runs-on: ubuntu-latest
          steps:
            - uses: actions/checkout@0123456789012345678901234567890123456789
    YAML
    success, stderr = verify(CONFIG, ".github/workflows/check.yaml" => workflow)
    assert success, stderr
  end

  def test_rejects_release_and_upload_actions
    [
      "goreleaser release --clean\n",
      "gh release upload v1.0.0 artifact.tar.gz\n",
      "uses: actions/upload-artifact@0123456789012345678901234567890123456789\n",
    ].each do |script|
      success, stderr = verify(CONFIG, ".github/workflows/publish.yaml" => script)
      refute success, script
      assert_includes stderr, "release or upload action"
    end
  end

  def test_rejects_repository_quarantine_bypass
    success, stderr = verify(
      CONFIG,
      "packaging/install.sh" => "xattr -dr com.apple.quarantine youtrack-agent-cli\n",
    )
    refute success
    assert_includes stderr, "Gatekeeper quarantine bypass"
  end

  def test_release_workflow_cannot_publish
    assert_equal({ "contents" => "read" }, RELEASE_WORKFLOW_CONFIG.fetch("permissions"))
    refute_match(/GITHUB_TOKEN|github\.token|goreleaser release|gh release|curl\b/i, RELEASE_WORKFLOW)
    steps = RELEASE_WORKFLOW_CONFIG.fetch("jobs").fetch("release-disabled").fetch("steps")
    assert_equal ["Refuse artifact publication"], steps.map { |step| step.fetch("name") }
  end

  def test_rejects_release_workflow_with_same_step_name_but_publication_payload
    workflow = <<~YAML
      name: release-disabled
      on:
        push:
          tags: ["v*"]
        workflow_dispatch:
      permissions:
        contents: read
      jobs:
        release-disabled:
          name: Distribution remains disabled
          permissions: write-all
          runs-on: ubuntu-latest
          steps:
            - name: Refuse artifact publication
              env:
                GH_TOKEN: ${{ github['token'] }}
              run: gh api --method POST repos/example/project/releases
    YAML
    success, stderr = verify(CONFIG, ".github/workflows/release.yaml" => workflow)
    refute success
    assert_includes stderr, "exact non-publishing release sentinel"
    assert_match(/permission/, stderr)
    assert_includes stderr, "publication credential reference"
    assert_includes stderr, "release or upload action"
  end

  def test_rejects_new_tag_workflow_with_bracket_secret_and_http_publication
    workflow = <<~YAML
      name: hidden-publisher
      on:
        push:
          tags: ["brew-v*"]
      permissions: read-all
      jobs:
        publish:
          runs-on: ubuntu-latest
          env:
            AUTH: ${{ secrets['PUBLISH_PAT'] }}
          steps:
            - run: curl --request POST --data artifact=ready https://example.invalid/publish
    YAML
    success, stderr = verify(CONFIG, ".github/workflows/homebrew-publish.yaml" => workflow)
    refute success
    assert_includes stderr, "tag or release trigger outside"
    assert_includes stderr, "forbidden workflow secrets context"
  end

  def test_rejects_derived_workflow_secret_expressions
    expressions = [
      "${{ (secrets).PUBLISH_PAT }}",
      "${{ fromJSON(toJSON(secrets))['PUBLISH_PAT'] }}",
    ]
    expressions.each_with_index do |expression, index|
      workflow = <<~YAML
        name: hidden-publisher
        on:
          push:
            branches: [main]
        permissions: read-all
        jobs:
          publish:
            runs-on: ubuntu-latest
            env:
              AUTH: #{expression}
            steps:
              - run: curl --request POST --data artifact=ready https://example.invalid/publish
      YAML
      success, stderr = verify(CONFIG, ".github/workflows/derived-secret-#{index}.yaml" => workflow)
      refute success, expression
      assert_includes stderr, "forbidden workflow secrets context"
    end
  end

  def test_homebrew_rehearsal_is_a_macos_only_offline_build_check
    steps = GO_WORKFLOW_CONFIG.fetch("jobs").fetch("test").fetch("steps")
    rehearsals = steps.select { |step| step.fetch("name", "") == "Homebrew offline-readiness rehearsal" }
    assert_equal 1, rehearsals.length

    rehearsal = rehearsals.first
    assert_equal "runner.os == 'macOS'", rehearsal.fetch("if")
    refute rehearsal.key?("env")

    script = rehearsal.fetch("run")
    download_offset = script.index("go mod download")
    check_offset = script.index("go run ./tools/homebrewcheck")
    refute_nil download_offset
    refute_nil check_offset
    assert_operator download_offset, :<, check_offset
    assert_includes script, '--proxy-dir "$(go env GOMODCACHE)/cache/download"'
    assert_match(/--build\s*\z/, script)
    refute_match(/(?:GITHUB_TOKEN|github\.token|secrets\.|HOMEBREW_.*TOKEN|TAP_.*TOKEN)/i, script)
  end

  def test_github_actions_are_pinned_to_commit_shas
    workflows = Dir.glob(File.join(ROOT, ".github/workflows/*.{yaml,yml}"))
    uses = workflows.flat_map { |workflow| File.read(workflow).scan(/^\s*uses:\s+([^\s#]+)/).flatten }
    refute_empty uses
    uses.each { |action| assert_match(/@[0-9a-f]{40}\z/, action) }
  end
end
