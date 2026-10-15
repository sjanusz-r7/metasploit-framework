# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Module::VersionCompatibility do
  subject do
    described_mixin = described_class
    klass = Class.new do
      include described_mixin

      attr_accessor :target
      attr_accessor :targets
    end

    klass.new
  end

  let(:payload_instance) do
    instance = instance_double(Msf::Payload)
    allow(instance).to receive(:platform_versions).and_return(payload_module_info['PlatformVersions'])
    instance
  end

  let(:target_with_opts) do
    target = double(Msf::Target)
    allow(target).to receive(:opts).and_return(target_opts)
    allow(target).to receive(:name).and_return('Mock Target')
    target
  end

  before do
    allow(subject).to receive(:target).and_return(target_with_opts)
  end

  # Helper to build a single-range PlatformVersions entry with just a minimum version.
  def platform_versions_from_min(runtime, min)
    { runtime => [Msf::Module::VersionRange.new(min: min)] }
  end

  describe '#version_compatibility_warnings' do
    context 'when the payload only declares an upper bound' do
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '3.0' } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => { 'python' => [Msf::Module::VersionRange.new(max: '2.7', exclude_max: true)] } }
      end

      it 'reports the maximum without implying a minimum' do
        expect(subject.version_compatibility_warnings(payload_instance)).to eq([
          'Payload supports Python versions < 2.7, but the target provides 3.0'
        ])
      end
    end

    context 'when automatic candidates span multiple supported ranges' do
      let(:target_opts) { { 'auto' => true } }
      let(:payload_module_info) do
        {
          'PlatformVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '3.0', exclude_max: true),
              Msf::Module::VersionRange.new(min: '3.1', max: '3.12')
            ]
          }
        }
      end

      before do
        subject.targets = [target_with_opts] + versions.map do |version|
          Msf::Target.new("Python #{version}", { 'PlatformVersions' => { 'python' => version } })
        end
      end

      context 'when a newer candidate falls in a gap' do
        let(:versions) { %w[2.6 3.0 3.1] }

        it 'warns about the incompatible candidate by name' do
          expect(subject.version_compatibility_warnings(payload_instance)).to eq([
            'Payload supports Python versions >= 2.5 and < 3.0 or >= 3.1 and <= 3.12, but the target provides 3.0 (target: Python 3.0)'
          ])
        end
      end

      context 'when a newer candidate exceeds the maximum' do
        let(:versions) { %w[2.7.18 3.13] }

        it 'warns about the candidate above the upper bound' do
          expect(subject.version_compatibility_warnings(payload_instance)).to eq([
            'Payload supports Python versions >= 2.5 and < 3.0 or >= 3.1 and <= 3.12, but the target provides 3.13 (target: Python 3.13)'
          ])
        end
      end

      context 'when every candidate is supported' do
        let(:versions) { %w[2.6 2.7.18 3.1 3.12] }

        it 'returns no warnings' do
          expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
        end
      end

      context 'when candidates lack version metadata' do
        let(:versions) { [] }

        before do
          subject.targets << Msf::Target.new('Unknown', {})
        end

        it 'does not infer incompatibility from missing metadata' do
          expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
        end
      end
    end

    context 'when target does not declare PlatformVersions' do
      let(:target_opts) { {} }
      let(:payload_module_info) do
        { 'Name' => 'Mock Payload', 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when payload does not declare PlatformVersions' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) { {} }

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target is nil' do
      let(:target_opts) { nil }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      before do
        allow(subject).to receive(:target).and_return(nil)
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version is below payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win2000 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(['Payload supports Windows versions >= Windows XP Service Pack 2 (5.1.2600.2), but the target provides Windows 2000 (5.0.2195)'])
      end
    end

    context 'when target version equals payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when target version exceeds payload minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Win7_SP0 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when versions are provided as strings' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => '5.0.2195' } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', '5.1.2600.2') }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(['Payload supports Windows versions >= Windows XP Service Pack 2 (5.1.2600.2), but the target provides Windows 2000 (5.0.2195)'])
      end
    end

    context 'when runtime keys do not overlap' do
      let(:target_opts) { { 'PlatformVersions' => { 'linux' => '5.4.0' } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple runtime keys both incompatible' do
      let(:target_opts) do
        {
          'PlatformVersions' => {
            'win' => Msf::WindowsVersion::XP_SP0,
            'python' => '2.7'
          }
        }
      end
      let(:payload_module_info) do
        {
          'PlatformVersions' => {
            'win' => [Msf::Module::VersionRange.new(min: Msf::WindowsVersion::XP_SP2)],
            'python' => [Msf::Module::VersionRange.new(min: '3.4')]
          }
        }
      end

      it 'returns warnings for each incompatible runtime' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(
          [
            'Payload supports Windows versions >= Windows XP Service Pack 2 (5.1.2600.2), but the target provides Windows XP (5.1.2600.0)',
            'Payload supports Python versions >= 3.4, but the target provides 2.7'
          ]
        )
      end
    end

    context 'with multiple version ranges where target falls in a later range' do
      # Python payload: supports 2.5-2.7 and 3.1+
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '3.6' } } }
      let(:payload_module_info) do
        {
          'PlatformVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns no warnings because 3.6 is within the 3.1+ range' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple version ranges where target falls in the first range' do
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '2.6' } } }
      let(:payload_module_info) do
        {
          'PlatformVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns no warnings because 2.6 is within the 2.5..2.7 range' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'with multiple version ranges where target falls in a gap' do
      # Python 3.0 is between 2.7 and 3.1 — unsupported
      let(:target_opts) { { 'PlatformVersions' => { 'python' => '3.0' } } }
      let(:payload_module_info) do
        {
          'PlatformVersions' => {
            'python' => [
              Msf::Module::VersionRange.new(min: '2.5', max: '2.7'),
              Msf::Module::VersionRange.new(min: '3.1')
            ]
          }
        }
      end

      it 'returns a warning because 3.0 is in the gap between ranges' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(['Payload supports Python versions >= 2.5 and <= 2.7 or >= 3.1, but the target provides 3.0'])
      end
    end

    context 'when Windows XP SP0/SP1 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP0 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns a warning' do
        warnings = subject.version_compatibility_warnings(payload_instance)
        expect(warnings).to eq(['Payload supports Windows versions >= Windows XP Service Pack 2 (5.1.2600.2), but the target provides Windows XP (5.1.2600.0)'])
      end
    end

    context 'when Windows XP SP2 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP2 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end

    context 'when Windows Server 2003 SP0 target is compared to Meterpreter minimum' do
      let(:target_opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::Server2003_SP0 } } }
      let(:payload_module_info) do
        { 'PlatformVersions' => platform_versions_from_min('win', Msf::WindowsVersion::XP_SP2) }
      end

      it 'returns no warnings because Server 2003 (5.2) is above XP SP2 (5.1)' do
        expect(subject.version_compatibility_warnings(payload_instance)).to be_empty
      end
    end
  end
end
