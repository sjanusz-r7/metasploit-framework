# frozen_string_literal: true

#
# Compare payload sizes between two git refs (e.g. master vs a PR branch).
#
# Uses Msf::Util::PayloadCachedSize module_options for consistent generation
# options, matching the framework's CachedSize constant methodology.
#
# The script uses `git worktree` to check out each ref in a temporary
# directory, so the user's working tree, index, and stash are never touched.
#
# Important: Run this script with plain `ruby`, not `bundle exec`:
#   ruby tools/dev/compare_payload_sizes.rb [--base-ref REF] [--head-ref REF] [--format FORMAT]
#
# Options:
#   --base-ref REF    Git ref for the baseline (default: master)
#   --head-ref REF    Git ref for the PR / comparison branch (default: HEAD)
#   --format FORMAT   Output format: 'markdown' or 'json' (default: markdown)
#
# Examples:
#   # Local comparison against master
#   ruby tools/dev/compare_payload_sizes.rb
#
#   # Compare two specific commits, JSON output
#   ruby tools/dev/compare_payload_sizes.rb --base-ref abc123 --head-ref def456 --format json
#

require 'fileutils'
require 'json'
require 'open3'
require 'optparse'
require 'tempfile'

class PayloadSizeComparator
  Result = Struct.new(:payload, :size_base, :size_head, :pct_change, :dynamic, :status, :error, keyword_init: true)

  # Status values:
  #   :added     — payload only exists on head ref
  #   :removed   — payload only exists on base ref
  #   :changed   — exists on both, size differs
  #   :unchanged — exists on both, same size
  #   :error     — generation failed on one or both sides
  STATUSES = %i[added removed changed unchanged error].freeze

  def initialize(base_ref:, head_ref:, format:)
    @base_ref    = base_ref
    @head_ref    = head_ref
    @format      = format
    @repo_root   = find_repo_root
    @worktrees   = []
  end

  def run
    install_cleanup_handlers

    $stderr.puts "[*] Collecting payload sizes for base ref: #{@base_ref}"
    base_sizes = collect_sizes_for_ref(@base_ref)

    $stderr.puts "[*] Collecting payload sizes for head ref: #{@head_ref}"
    head_sizes = collect_sizes_for_ref(@head_ref)

    $stderr.puts "[*] Comparing #{base_sizes.size} base payloads with #{head_sizes.size} head payloads"
    results = compare(base_sizes, head_sizes)

    output(results)
  ensure
    cleanup_worktrees
  end

  private

  def find_repo_root
    root = File.expand_path(File.join(__dir__, '..', '..'))
    unless File.exist?(File.join(root, 'msfvenom'))
      abort "Error: Cannot locate metasploit-framework root (expected at #{root})"
    end
    root
  end

  # Installs a SIGINT trap and at_exit hook so worktrees are cleaned up even
  # if the user presses Ctrl+C or the process exits unexpectedly.
  def install_cleanup_handlers
    comparator = self

    Signal.trap('INT') do
      $stderr.puts "\n[!] Interrupted — cleaning up worktrees..."
      comparator.send(:cleanup_worktrees)
      exit(130) # 128 + SIGINT(2), standard convention
    end

    at_exit do
      comparator.send(:cleanup_worktrees)
    end
  end

  # Removes all temporary worktree directories and prunes git's worktree
  # list. Safe to call multiple times.
  def cleanup_worktrees
    @worktrees.each do |dir|
      next unless File.directory?(dir)

      $stderr.puts "[*] Removing worktree #{dir}"
      FileUtils.rm_rf(dir)
    end
    @worktrees.clear

    # Tell git to clean up its worktree bookkeeping
    git('worktree', 'prune', allow_failure: true)
  end

  # Creates a temporary git worktree for the given ref, installs gems, and
  # generates all payload sizes from that worktree. The user's working tree,
  # index, and stash are never modified.
  def collect_sizes_for_ref(ref)
    worktree_dir = create_worktree(ref)
    bundle_install(worktree_dir)
    generate_all_payload_sizes(worktree_dir)
  end

  # Creates a detached worktree for the given ref in a temp directory.
  # Returns the path to the worktree.
  def create_worktree(ref)
    dir = File.join(Dir.tmpdir, "msf_payload_sizes_#{ref.gsub(/[^a-zA-Z0-9_.-]/, '_')}_#{$$}")
    FileUtils.rm_rf(dir) if File.exist?(dir)

    $stderr.puts "[*] Creating worktree at #{dir} for #{ref}"
    git('worktree', 'add', '--detach', dir, ref)
    @worktrees << dir
    dir
  end

  # Runs bundle install inside the worktree so the subprocess picks up the
  # correct gem versions from that ref's Gemfile.lock.
  def bundle_install(worktree_dir)
    $stderr.puts "[*] Running bundle install in #{worktree_dir}..."
    _stdout, stderr, status = run_unbundled('bundle', 'install', '--quiet', chdir: worktree_dir)
    unless status.success?
      $stderr.puts "[!] bundle install failed:\n#{stderr}"
    end
  end

  # Shells out to a child Ruby process inside the worktree with a clean
  # Bundler environment so the framework is loaded from that ref's code and
  # gems.
  def generate_all_payload_sizes(worktree_dir)
    script = build_size_collection_script
    sizes = {}

    Tempfile.create(['payload_sizes', '.rb']) do |f|
      f.write(script)
      f.flush

      stdout, stderr, status = run_unbundled(
        'bundle', 'exec', 'ruby', f.path, worktree_dir,
        chdir: worktree_dir
      )

      $stderr.puts stderr unless stderr.empty?

      unless status.success?
        $stderr.puts "[!] Size collection failed (exit #{status.exitstatus})"
        return sizes
      end

      begin
        sizes = JSON.parse(stdout)
      rescue JSON::ParserError => e
        $stderr.puts "[!] Failed to parse size output: #{e.message}"
      end
    end

    sizes
  end

  # Runs a command with a fully clean environment — all Bundler and RubyGems
  # env vars are reset so the child process discovers gems from the
  # worktree's Gemfile/Gemfile.lock.
  def run_unbundled(*cmd, chdir: @repo_root)
    env_overrides = {}
    env_overrides['BUNDLE_WITHOUT'] = ENV['BUNDLE_WITHOUT'] if ENV['BUNDLE_WITHOUT']

    if defined?(Bundler)
      Bundler.with_unbundled_env do
        ENV.update(env_overrides)
        Open3.capture3(*cmd, chdir: chdir)
      end
    else
      env = ENV.to_h.dup
      # Strip everything Bundler and RubyGems inject
      env.delete_if { |k, _| k =~ /\A(BUNDLE|BUNDLER|GEM_|RUBYOPT|RUBYLIB|_ORIGINAL_GEM_)/ }
      env.merge!(env_overrides)
      Open3.capture3(env, *cmd, chdir: chdir)
    end
  end

  # Builds a self-contained Ruby script that boots the framework and uses
  # Msf::Util::PayloadCachedSize module_options for consistent generation
  # options, but always generates a real size (including dynamic payloads).
  #
  # The script receives the worktree root as ARGV[0] and uses it to locate
  # the Gemfile and lib directory.
  #
  # Output is JSON on stdout. Each payload gets an entry regardless of whether
  # generation succeeded, so the caller can distinguish "payload exists but
  # failed" from "payload does not exist on this ref":
  #   { "payload/name": { "size": 123, "dynamic": false, "error": null }, ... }
  def build_size_collection_script
    <<~'RUBY'
      # frozen_string_literal: true
      worktree_root = ARGV[0] || __dir__

      ENV['BUNDLE_GEMFILE'] = File.expand_path('Gemfile', worktree_root)
      require 'bundler/setup'

      if defined?(Warning) && Warning.respond_to?(:[]=)
        Warning[:deprecated] = false
      end

      $:.unshift(File.expand_path('lib', worktree_root))

      require 'msfenv'
      require 'rex'
      require 'msf/util/payload_cached_size'
      require 'json'

      framework = Msf::Simple::Framework.create(
        module_types: [Msf::MODULE_PAYLOAD, Msf::MODULE_ENCODER, Msf::MODULE_NOP]
      )

      results = {}
      payload_names = framework.payloads.module_refnames.sort

      $stderr.puts "[*] Generating #{payload_names.size} payloads..."

      payload_names.each_with_index do |payload_name, idx|
        if (idx + 1) % 50 == 0
          $stderr.puts "[*] Progress: #{idx + 1}/#{payload_names.size}"
        end

        begin
          mod = framework.payloads.create(payload_name)
          unless mod
            $stderr.puts "[-] #{payload_name}: failed to create module"
            results[payload_name] = { 'size' => nil, 'dynamic' => false, 'error' => 'failed to create module' }
            next
          end

          dynamic = Msf::Util::PayloadCachedSize.is_dynamic?(framework, mod)
          opts = Msf::Util::PayloadCachedSize.module_options(mod)
          size = mod.replicant.generate_simple(opts).bytesize

          results[payload_name] = { 'size' => size, 'dynamic' => dynamic, 'error' => nil }
        rescue => e
          $stderr.puts "[-] #{payload_name}: #{e.message}"
          results[payload_name] = { 'size' => nil, 'dynamic' => false, 'error' => e.message }
          next
        end
      end

      $stdout.puts JSON.generate(results)
    RUBY
  end

  def compare(base_sizes, head_sizes)
    all_payloads = (base_sizes.keys + head_sizes.keys).uniq.sort

    all_payloads.map do |name|
      in_base = base_sizes.key?(name)
      in_head = head_sizes.key?(name)

      base_entry = base_sizes[name]
      head_entry = head_sizes[name]

      base_size    = base_entry&.fetch('size', nil)
      head_size    = head_entry&.fetch('size', nil)
      base_dynamic = base_entry&.fetch('dynamic', false)
      head_dynamic = head_entry&.fetch('dynamic', false)
      base_error   = base_entry&.fetch('error', nil)
      head_error   = head_entry&.fetch('error', nil)

      status, pct = classify(in_base, in_head, base_size, head_size, base_error, head_error)

      Result.new(
        payload:    name,
        size_base:  base_size,
        size_head:  head_size,
        pct_change: pct,
        dynamic:    base_dynamic || head_dynamic,
        status:     status,
        error:      [base_error, head_error].compact.first
      )
    end
  end

  def classify(in_base, in_head, base_size, head_size, base_error, head_error)
    # Payload only on one side
    return [:added, nil]   if !in_base && in_head
    return [:removed, nil] if in_base && !in_head

    # Present on both sides but generation failed on at least one
    return [:error, nil] if base_error || head_error

    # Both generated successfully
    if base_size == head_size
      [:unchanged, 0.0]
    elsif base_size && base_size > 0
      [:changed, (((head_size - base_size).to_f / base_size) * 100).round(2)]
    else
      [:changed, 0.0]
    end
  end

  def output(results)
    case @format
    when 'json'
      puts JSON.pretty_generate(results.map(&:to_h))
    when 'markdown'
      puts format_markdown(results)
    else
      abort "Unknown format: #{@format}"
    end
  end

  def format_markdown(results)
    lines = []
    lines << "## Payload Size Comparison"
    lines << ""
    lines << "Base ref: `#{@base_ref}` | Head ref: `#{@head_ref}`"
    lines << ""

    changed   = results.select { |r| r.status == :changed }
    added     = results.select { |r| r.status == :added }
    removed   = results.select { |r| r.status == :removed }
    errors    = results.select { |r| r.status == :error }
    unchanged = results.select { |r| r.status == :unchanged }

    if changed.empty? && added.empty? && removed.empty? && errors.empty?
      lines << "No payload size changes detected."
      return lines.join("\n")
    end

    unless changed.empty?
      lines << "<details>"
      lines << "<summary>Changed payloads (#{changed.size})</summary>"
      lines << ""
      lines << "| Payload | Size (master) | Size (PR) | % change |"
      lines << "|---------|--------------|-----------|----------|"
      changed.sort_by { |r| -(r.pct_change&.abs || 0) }.each do |r|
        sign = r.pct_change >= 0 ? '+' : ''
        dyn = r.dynamic ? ' ⚡' : ''
        lines << "| `#{r.payload}`#{dyn} | #{r.size_base} | #{r.size_head} | #{sign}#{r.pct_change}% |"
      end
      lines << ""
      lines << "</details>"
      lines << ""
    end

    unless added.empty?
      lines << "<details>"
      lines << "<summary>New payloads (#{added.size})</summary>"
      lines << ""
      lines << "| Payload | Size (PR) |"
      lines << "|---------|-----------|"
      added.sort_by(&:payload).each do |r|
        dyn = r.dynamic ? ' ⚡' : ''
        size_col = r.size_head ? r.size_head.to_s : 'error'
        lines << "| `#{r.payload}`#{dyn} | #{size_col} |"
      end
      lines << ""
      lines << "</details>"
      lines << ""
    end

    unless removed.empty?
      lines << "<details>"
      lines << "<summary>Removed payloads (#{removed.size})</summary>"
      lines << ""
      lines << "| Payload | Size (master) |"
      lines << "|---------|--------------|"
      removed.sort_by(&:payload).each do |r|
        dyn = r.dynamic ? ' ⚡' : ''
        size_col = r.size_base ? r.size_base.to_s : 'error'
        lines << "| `#{r.payload}`#{dyn} | #{size_col} |"
      end
      lines << ""
      lines << "</details>"
      lines << ""
    end

    unless errors.empty?
      lines << "<details>"
      lines << "<summary>Generation errors (#{errors.size})</summary>"
      lines << ""
      lines << "| Payload | Size (master) | Size (PR) | Error |"
      lines << "|---------|--------------|-----------|-------|"
      errors.sort_by(&:payload).each do |r|
        base_col = r.size_base ? r.size_base.to_s : '—'
        head_col = r.size_head ? r.size_head.to_s : '—'
        lines << "| `#{r.payload}` | #{base_col} | #{head_col} | #{r.error} |"
      end
      lines << ""
      lines << "</details>"
      lines << ""
    end

    dynamic_count = results.count(&:dynamic)
    lines << "**Summary:** #{changed.size} changed, #{added.size} new, #{removed.size} removed, #{errors.size} errors, #{unchanged.size} unchanged out of #{results.size} total payloads."
    lines << "" if dynamic_count > 0
    lines << "⚡ = dynamic payload (size varies between generations) — #{dynamic_count} total" if dynamic_count > 0

    lines.join("\n")
  end

  def git(*args, allow_failure: false)
    cmd = ['git'] + args
    stdout, stderr, status = Open3.capture3(*cmd, chdir: @repo_root)
    unless status.success? || allow_failure
      abort "Git command failed: #{cmd.join(' ')}\n#{stderr}"
    end
    stdout.strip
  end
end

# --- CLI entry point ---

if __FILE__ == $PROGRAM_NAME
  options = {
    base_ref: 'master',
    head_ref: 'HEAD',
    format:   'markdown'
  }

  OptionParser.new do |opts|
    opts.banner = "Usage: ruby #{$PROGRAM_NAME} [options]"

    opts.on('--base-ref REF', "Git ref for the baseline (default: #{options[:base_ref]})") do |v|
      options[:base_ref] = v
    end

    opts.on('--head-ref REF', "Git ref for the comparison branch (default: #{options[:head_ref]})") do |v|
      options[:head_ref] = v
    end

    opts.on('--format FORMAT', %w[markdown json], "Output format: markdown, json (default: #{options[:format]})") do |v|
      options[:format] = v
    end

    opts.on('-h', '--help', 'Show this help') do
      puts opts
      exit
    end
  end.parse!

  comparator = PayloadSizeComparator.new(
    base_ref: options[:base_ref],
    head_ref: options[:head_ref],
    format:   options[:format]
  )

  comparator.run
end
