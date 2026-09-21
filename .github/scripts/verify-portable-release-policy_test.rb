#!/usr/bin/env ruby

require "fileutils"
require "minitest/autorun"
require "open3"
require "tmpdir"
require "yaml"

class VerifyPortableReadOnlyReleasePolicyTest < Minitest::Test
  ROOT = File.expand_path("../..", __dir__)
  VERIFIER = File.join(__dir__, "verify-portable-release-policy.rb")
  CONFIG = YAML.safe_load(File.read(File.join(ROOT, ".goreleaser.yaml")), permitted_classes: [], aliases: false)
  RELEASE = File.read(File.join(ROOT, ".github/workflows/release.yaml"))

  def verify(config = CONFIG, files = {}, release: RELEASE)
    Dir.mktmpdir("portable-release-policy") do |root|
      config_path = File.join(root, ".goreleaser.yaml")
      File.write(config_path, YAML.dump(config))
      files.each do |relative, content|
        target = File.join(root, relative)
        FileUtils.mkdir_p(File.dirname(target))
        File.write(target, content)
      end
      FileUtils.mkdir_p(File.join(root, ".github/workflows"))
      File.write(File.join(root, ".github/workflows/release.yaml"), release)
      _stdout, stderr, status = Open3.capture3("ruby", VERIFIER, config_path, root)
      [status.success?, stderr]
    end
  end

  def test_current_configuration_passes
    success, stderr = verify
    assert success, stderr
  end

  def test_release_config_selects_only_portable_readonly_build
    build = CONFIG.fetch("builds").fetch(0)
    assert_equal ["portable_readonly"], build.fetch("tags")
    assert_equal ["CGO_ENABLED=0"], build.fetch("env")
    assert_equal ["linux"], build.fetch("goos")
    assert_equal %w[amd64 arm64], build.fetch("goarch")
    assert_equal ["tar.gz"], CONFIG.fetch("archives").fetch(0).fetch("formats")
    refute CONFIG.key?("homebrew")
    refute CONFIG.key?("homebrew_casks")
  end

  def test_rejects_a_nonportable_build_tag
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").fetch(0)["tags"] = ["ordinary"]
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "invalid tags"
  end

  def test_rejects_cgo_or_windows_portable_build
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("builds").fetch(0)["env"] = ["CGO_ENABLED=1"]
    changed.fetch("builds").fetch(0)["goos"] << "windows"
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "invalid env"
    assert_includes stderr, "invalid goos"
  end

  def test_rejects_release_config_hooks_or_extra_archive_files
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed["before"] = { "hooks" => ["curl https://example.invalid"] }
    changed.fetch("archives").fetch(0)["files"] = ["private/*"]
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "unapproved top-level section"
    assert_includes stderr, "must publish only portable read-only tar.gz archives"
  end

  def test_rejects_extra_release_assets_or_checksum_settings
    changed = Marshal.load(Marshal.dump(CONFIG))
    changed.fetch("release")["extra_files"] = [{ "glob" => "README.md" }]
    changed.fetch("checksum")["algorithm"] = "sha512"
    success, stderr = verify(changed)
    refute success
    assert_includes stderr, "target only the canonical GitHub repository"
    assert_includes stderr, "only the approved checksum"
  end

  def test_rejects_homebrew_and_quarantine_workarounds
    success, stderr = verify(CONFIG, "Formula/youtrack-agent-cli.rb" => "class YoutrackAgentCli < Formula; end\n")
    refute success
    assert_includes stderr, "Homebrew Formula/Cask"

    success, stderr = verify(CONFIG, "packaging/install.sh" => "xattr -dr com.apple.quarantine binary\n")
    refute success
    assert_includes stderr, "quarantine bypass"
  end

  def test_rejects_unrelated_publisher
    workflow = <<~YAML
      name: upload
      on:
        push:
          tags: ["v*"]
      permissions:
        contents: write
      jobs:
        publish:
          runs-on: ubuntu-latest
          steps:
            - run: gh release create v0.1.0
    YAML
    success, stderr = verify(CONFIG, ".github/workflows/other.yaml" => workflow)
    refute success
    assert_includes stderr, "must set read-only permissions"
    assert_includes stderr, "publication action"
  end

  def test_release_workflow_is_v0_tag_only_and_scoped
    workflow = YAML.safe_load(RELEASE, permitted_classes: [], aliases: false)
    assert_equal({ "contents" => "read" }, workflow.fetch("permissions"))
    assert_equal({ "push" => { "tags" => ["v0.*"] } }, workflow.fetch(true))
    assert_equal "verify-portable-readonly", workflow.fetch("jobs").fetch("publish-portable-readonly").fetch("needs")
    assert_equal({ "contents" => "write" }, workflow.fetch("jobs").fetch("publish-portable-readonly").fetch("permissions"))
    assert_equal 2, RELEASE.scan("persist-credentials: false").length
    refute_match(/homebrew|xattr|secrets\./i, RELEASE)
    assert_includes RELEASE, "-tags portable_readonly"
  end

  def test_rejects_a_second_upload_path_in_release_workflow
    changed = RELEASE.sub("run: goreleaser release --clean --config .goreleaser.yaml", "run: goreleaser release --clean --config .goreleaser.yaml\n      - run: curl -T artifact https://example.invalid")
    success, stderr = verify(CONFIG, {}, release: changed)
    refute success
    assert_includes stderr, "must equal the approved portable read-only publisher"
  end
end
