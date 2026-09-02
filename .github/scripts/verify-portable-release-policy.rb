#!/usr/bin/env ruby

require "yaml"
require "pathname"

ALLOWED_WORKFLOW_ACTIONS = %w[
  actions/checkout
  actions/setup-go
  actions/setup-python
].freeze

EXPECTED_RELEASE_WORKFLOW = {
  "name" => "release-disabled",
  true => {
    "push" => { "tags" => ["v*"] },
    "workflow_dispatch" => nil,
  },
  "permissions" => { "contents" => "read" },
  "jobs" => {
    "release-disabled" => {
      "name" => "Distribution remains disabled",
      "runs-on" => "ubuntu-latest",
      "steps" => [{
        "name" => "Refuse artifact publication",
        "run" => "echo \"Distribution is disabled until Gate 1A and signed macOS packaging pass review.\"\n",
      }],
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
  warn "disabled release policy: cannot read #{path}: #{error.message}"
  exit 1
end

expected = {
  "version" => 2,
  "project_name" => "youtrack-agent-cli",
  "builds" => [{ "id" => "distribution-disabled", "skip" => true }],
}

strings = lambda do |value|
  case value
  when Hash
    value.each_value.flat_map { |item| strings.call(item) }
  when Array
    value.flat_map { |item| strings.call(item) }
  when String
    [value]
  else
    []
  end
end

errors = []
errors << "configuration must contain only the fail-closed sentinel" unless config == expected
if strings.call(config).any? { |value| value.match?(/(?:\bxattr\b|com\.apple\.quarantine)/i) }
  errors << "configuration contains a Gatekeeper quarantine bypass"
end

formula_paths = Dir.glob(
  File.join(root, "{Formula,Cask,Casks}/**/*.rb"),
  File::FNM_EXTGLOB,
)
formula_paths.each do |candidate|
  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  errors << "active Homebrew Formula/Cask is forbidden before Gate 1A: #{relative}"
end


allowed_ruby_paths = %w[
  .github/scripts/verify-portable-release-policy.rb
  .github/scripts/verify-portable-release-policy_test.rb
].freeze
Dir.glob(File.join(root, "**/*.rb"), File::FNM_DOTMATCH).each do |candidate|
  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  next if relative.start_with?(".git/") || allowed_ruby_paths.include?(relative)

  errors << "Ruby packaging/release file is forbidden before Gate 1A: #{relative}"
end

release_surface = [
  File.join(root, ".github/workflows/**/*"),
  File.join(root, ".github/scripts/**/*"),
  File.join(root, "packaging/**/*"),
  File.join(root, "scripts/**/*"),
  File.join(root, "tools/homebrewcheck/**/*"),
  File.join(root, "*.rb"),
].flat_map { |glob| Dir.glob(glob) }.uniq.sort

release_surface.each do |candidate|
  next unless File.file?(candidate)

  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  # These two files define and test this scanner, so their regular-expression
  # fixtures necessarily contain the forbidden tokens. All readiness inputs,
  # including tools/homebrewcheck, remain subject to the content scan.
  next if relative == ".github/scripts/verify-portable-release-policy.rb" ||
    relative == ".github/scripts/verify-portable-release-policy_test.rb"

  content = File.binread(candidate).force_encoding(Encoding::UTF_8).scrub
  if File.extname(candidate) == ".rb" && content.match?(/(?:<\s*Formula\b|^\s*cask\s+["'][^"']+["']\s+do\b)/i)
    errors << "active Homebrew Formula/Cask is forbidden before Gate 1A: #{relative}"
  end
  if content.match?(/(?:\bxattr\b|com\.apple\.quarantine|--no-quarantine|spctl\s+--master-disable)/i)
    errors << "#{relative} contains a Gatekeeper quarantine bypass"
  end
  if content.match?(/(?:\bHOMEBREW_[A-Z0-9_]*TOKEN\b|\bTAP_[A-Z0-9_]*TOKEN\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b|github(?:\.token|\[['"]token['"]\])|secrets\.[A-Za-z0-9_]+)/i)
    errors << "#{relative} contains a publication credential reference"
  end
  if content.match?(/(?:\bbrew\s+(?:tap|tap-new|create|bump-formula-pr|bump-cask-pr)\b|\bgit\s+push\b)/i)
    errors << "#{relative} contains a Homebrew tap write"
  end
  if content.match?(/(?:\bgoreleaser\s+release\b|\bgh\s+(?:api\b|release\s+(?:create|upload)\b)|\bcurl\b[^\n]*(?:--upload-file|-T\s)|\b(?:aws\s+s3|gsutil)\s+cp\b|\/upload-artifact@|action-gh-release|goreleaser-action)/i)
    errors << "#{relative} contains a release or upload action"
  end
  if content.match?(/^\s*(?:contents|packages|id-token|attestations):\s*write\s*$/i)
    errors << "#{relative} grants publication write permission"
  end
end

workflow_paths = Dir.glob(File.join(root, ".github/workflows/*.{yaml,yml}"))
workflow_paths.each do |candidate|
  relative = Pathname.new(candidate).relative_path_from(Pathname.new(root)).to_s
  begin
    workflow = YAML.safe_load(File.read(candidate), permitted_classes: [], aliases: false)
  rescue Psych::Exception => error
    errors << "#{relative} is not safe, parseable workflow YAML: #{error.message}"
    next
  end
  unless workflow.is_a?(Hash)
    errors << "#{relative} must contain a workflow mapping"
    next
  end
  if relative == ".github/workflows/release.yaml" && workflow != EXPECTED_RELEASE_WORKFLOW
    errors << "#{relative} must equal the exact non-publishing release sentinel"
  end
  if relative != ".github/workflows/release.yaml"
    triggers = workflow[true] || workflow["on"]
    release_trigger = case triggers
                      when String
                        triggers == "release"
                      when Array
                        triggers.map(&:to_s).include?("release")
                      when Hash
                        push = triggers["push"]
                        triggers.key?("release") ||
                          (push.is_a?(Hash) && (push.key?("tags") || push.key?("tags-ignore")))
                      else
                        false
                      end
    if release_trigger
      errors << "#{relative} has a tag or release trigger outside the disabled release sentinel"
    end
  end
  unless workflow.key?("permissions")
    errors << "#{relative} must set explicit read-only top-level permissions"
  end

  visit = lambda do |value|
    case value
    when Hash
      value.each do |key, item|
        if key.to_s == "permissions"
          case item
          when String
            unless item == "read-all"
              errors << "#{relative} has non-read-only workflow permissions"
            end
          when Hash
            unless item.values.all? { |level| %w[read none].include?(level.to_s) }
              errors << "#{relative} grants publication write permission"
            end
          else
            errors << "#{relative} has invalid workflow permissions"
          end
        end
        if key.to_s == "uses"
          action, revision = item.to_s.split("@", 2)
          unless ALLOWED_WORKFLOW_ACTIONS.include?(action)
            errors << "#{relative} uses unapproved workflow action #{action.inspect}"
          end
          unless revision&.match?(/\A[0-9a-f]{40}\z/)
            errors << "#{relative} uses an action that is not pinned to a commit SHA"
          end
        end
        visit.call(item)
      end
    when Array
      value.each { |item| visit.call(item) }
    when String
      if value.match?(/\$\{\{.*\bsecrets\b/im)
        errors << "#{relative} references the forbidden workflow secrets context"
      end
    end
  end
  visit.call(workflow)
end

if errors.empty?
  puts "disabled release policy ok"
  exit 0
end

errors.each { |error| warn "disabled release policy: #{error}" }
exit 1
