# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/version'

#
# Provides a wrapper around a minimum and maximum version range.
# Either bound may be omitted. With neither bound, every valid version is
# contained in the range.
#
class Msf::Module::VersionRange

  # @param min [String, Integer, Rex::Version, nil] Optional lower bound.
  # @param max [String, Integer, Rex::Version, nil] Optional upper bound.
  # @param exclude_max [Boolean] Whether the upper bound is exclusive.
  def initialize(min: nil, max: nil, exclude_max: false)
    raise ArgumentError, 'Invalid minimum version' unless min.nil? || valid_version_value?(min)
    raise ArgumentError, 'Invalid maximum version' unless max.nil? || valid_version_value?(max)

    self.min = min.nil? ? nil : to_version(min)
    self.max = max.nil? ? nil : to_version(max)
    raise ArgumentError, 'Maximum version precedes minimum version' if self.min && self.max && self.max < self.min

    @exclude_max = exclude_max
  end

  # Check whether a value is acceptable as a version argument.
  # Rex::Version is quite funky:
  #   Rex::Version.new(nil).to_s -> "0"
  #   Rex::Version.new('nil') raises ArgumentError
  # So we must guard against nil and non-numeric strings before creating Rex::Version.
  #
  # @param value [String, Integer, Rex::Version, nil] The value to check.
  # @return [Boolean]
  def self.valid_version_value?(value)
    return false if value.nil?
    return true if value.is_a?(Rex::Version)
    return true if value.is_a?(Integer)

    return false unless value.is_a?(String)
    return false if value.empty?

    begin
      Rex::Version.new(value)
      true
    rescue ArgumentError
      false
    end
  end

  # Does this version range contain the specified version?
  # A version is contained if it is >= min and, if a max is defined, <= max
  # (or < max when exclude_max is true).
  #
  # @param version [String, Integer, Rex::Version] The version to check.
  # @return [Boolean, nil] true/false, or nil if the version value is invalid.
  def contains?(version)
    return nil unless valid_version_value?(version)

    ver = to_version(version)

    return false if min && ver < min
    return true if max.nil?

    exclude_max ? ver < max : ver <= max
  end

  # Describe both bounds, optionally formatting versions for display.
  #
  # @yieldparam version [Rex::Version] A bound to format.
  # @yieldreturn [String] The displayed version.
  # @return [String] A description of the supported versions.
  def description(&formatter)
    formatter ||= lambda(&:to_s)
    bounds = []
    bounds << ">= #{formatter.call(min)}" if min
    bounds << "#{exclude_max ? '<' : '<='} #{formatter.call(max)}" if max
    bounds.empty? ? 'any version' : bounds.join(' and ')
  end

  # Normalize a value to Rex::Version.
  #
  # @param value [String, Integer, Rex::Version] The version to normalize.
  # @return [Rex::Version]
  def self.to_version(value)
    value.is_a?(Rex::Version) ? value : Rex::Version.new(value.to_s)
  end

  # @return [Rex::Version, nil] The minimum version (inclusive), or nil for unbounded.
  attr_accessor :min

  # @return [Rex::Version, nil] The upper bound, or nil for unbounded.
  attr_accessor :max

  # @return [Boolean] Whether the upper bound is exclusive.
  attr_reader :exclude_max

  private

  def to_version(value)
    self.class.to_version(value)
  end

  def valid_version_value?(value)
    self.class.valid_version_value?(value)
  end

end
