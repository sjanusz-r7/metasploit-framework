# -*- coding: binary -*-
# frozen_string_literal: true

#
# Infers platform version metadata (the 'PlatformVersions' target option) from a
# human-readable exploit target name.
#
# The 'PlatformVersions' hash is keyed by platform name (e.g. 'win',
# 'python') and consumed by Msf::Module::VersionCompatibility to warn when a
# payload's minimum supported version is newer than the version a target
# provides.
#
# Only Windows inference is implemented today, but the registry below is the
# single extension point: supporting a new platform (macOS, Linux, ...) is a
# matter of adding one Inferrer that knows its platform key, which platforms it
# applies to, and how to turn a target name into a Rex::Version.
#
module Msf::Module::PlatformVersionInference
  #
  # Describes how to infer a single platform's version from a target name.
  #
  # @!attribute platform
  #   @return [String] The 'PlatformVersions' hash key this inferrer populates.
  # @!attribute platform_pattern
  #   @return [Regexp, nil] Matched against a target's declared platform names.
  #     When it matches none of them the inferrer is skipped; nil means the
  #     inferrer is not platform gated.
  # @!attribute resolver
  #   @return [#call] A callable taking the target name and returning a
  #     Rex::Version or nil.
  #
  Inferrer = Struct.new(:platform, :platform_pattern, :resolver) do
    # Resolve the platform version for the supplied target name.
    #
    # @param name [String] The exploit target name.
    # @return [Rex::Version, nil]
    def infer(name)
      resolver.call(name)
    end

    # Whether this inferrer applies to a target declaring the given platform
    # names. When the target declares no platform we fall back to name-based
    # inference (return true), and an inferrer with no platform_pattern is
    # always considered applicable.
    #
    # @param platform_names [Array<String>, nil] Lower-cased platform names.
    # @return [Boolean]
    def applicable_to_platforms?(platform_names)
      return true if platform_names.nil? || platform_names.empty?
      return true if platform_pattern.nil?

      platform_names.any? { |platform_name| platform_pattern.match?(platform_name) }
    end
  end

  # The ordered list of registered inferrers. Add new platforms here.
  INFERRERS = [
    Inferrer.new('win', /\Awin\z/, ->(name) { Msf::WindowsVersion.from_target_name(name) })
  ].freeze

  module_function

  # Infer platform versions for a target name.
  #
  # @param name [String] The exploit target name.
  # @param existing [Hash] Platform versions already set (e.g. manually in module
  #   metadata). Platforms present here are never overwritten.
  # @param platform_names [Array<String>, nil] The target's declared platform
  #   names (lower-cased), used to skip inferrers for other platforms. Nil when
  #   the target declares no platform.
  # @return [Hash] A hash of platform name => Rex::Version for the platforms that
  #   could be inferred. Empty when nothing could be inferred.
  def infer(name, existing: {}, platform_names: nil)
    inferred = {}

    INFERRERS.each do |inferrer|
      # Respect any explicitly supplied version for this platform.
      next if existing.key?(inferrer.platform)
      next unless inferrer.applicable_to_platforms?(platform_names)

      version = inferrer.infer(name)
      inferred[inferrer.platform] = version unless version.nil?
    end

    inferred
  end
end
