# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/version'

#
# Provides version compatibility checks between exploit targets and payloads.
#
module Msf::Module::VersionCompatibility
  # Check version compatibility between a payload and the current exploit target.
  #
  # A payload declares its supported versions as a Hash of platform name to an Array of
  # VersionRange objects (PlatformVersions). A target version is considered compatible
  # when it falls within at least one of the declared ranges for that platform.
  #
  # @param payload_instance [Msf::Payload] A payload module instance.
  # @return [Array<String>] An array of warning strings. Empty means the payload is compatible.
  def version_compatibility_warnings(payload_instance)
    warnings = []

    supported = payload_instance.platform_versions
    return warnings unless supported.is_a?(Hash) && !supported.empty?

    compatibility_targets.each do |candidate|
      target_versions = candidate.opts['PlatformVersions']
      next unless target_versions.is_a?(Hash) && !target_versions.empty?

      supported.each do |platform, ranges|
        next unless target_versions.key?(platform)
        next unless ranges.is_a?(Array) && !ranges.empty?

        target_ver = to_version(target_versions[platform])

        # Each possible target must fall within a supported range. Checking only
        # the oldest target misses gaps and upper bounds in the payload ranges.
        next if ranges.any? { |range| range.contains?(target_ver) }

        requirements = ranges.map do |range|
          range.description { |version| human_readable_version_string(platform, version) }
        end.join(' or ')
        target_name = human_readable_version_string(platform, target_ver)
        platform_name = Msf::Module::Platform.find_platform(platform).realname
        warning = "Payload supports #{platform_name} versions #{requirements}, but the target provides #{target_name}"
        warning << " (target: #{candidate.name})" if target.opts['auto']
        warnings << warning
      end
    end

    warnings.uniq
  end

  private

  # Normalize a value to Rex::Version
  #
  # @param value [String, Rex::Version] The version to normalize.
  # @return [Rex::Version]
  def to_version(value)
    value.is_a?(Rex::Version) ? value : Rex::Version.new(value.to_s)
  end

  # Map a platform (Windows, Python etc.) and a version to a human-readable string.
  # For example 'win', '5.1.2600.2' would get mapped to 'Windows XP Service Pack 2 (5.1.2600.2)'
  #
  # @param platform [String] The platform key (e.g., 'win', 'python').
  # @param version [Rex::Version] The version to look up.
  # @return [String] A human-readable string
  def human_readable_version_string(platform, version)
    case platform
    when 'win'
      name = windows_version_name(version)
      return "#{name} (#{version})" if name
    end

    version.to_s
  end

  # Look up a Windows version's human-readable name from the WindowsVersion mappings.
  #
  # @param version [Rex::Version] The version to look up.
  # @return [String, nil] The friendly name, or nil if not found.
  def windows_version_name(version)
    [
      { klass: Msf::WindowsVersion::WorkstationSpecificVersions, mapping: Msf::WindowsVersion::WorkstationNameMapping },
      { klass: Msf::WindowsVersion::ServerSpecificVersions, mapping: Msf::WindowsVersion::ServerNameMapping }
    ].each do |h|
      h[:klass].constants.each do |const|
        return h[:mapping][const] if h[:klass].const_get(const) == version
      end
    end

    nil
  end

  # Retrieve the targets that may be selected. Automatic targets must check
  # every concrete candidate, including candidates above the lowest version.
  #
  # @return [Array<Msf::Module::Target>] The active target or automatic candidates.
  def compatibility_targets
    return [] unless respond_to?(:target) && target
    return [target] unless target.opts['auto'] && respond_to?(:targets) && targets.is_a?(Array)

    targets.reject { |candidate| candidate.opts['auto'] }
  end
end
