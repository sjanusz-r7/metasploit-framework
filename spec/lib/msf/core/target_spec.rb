require 'spec_helper'

RSpec.describe Msf::Target do
  it 'is an alias for Msf::Module::Target' do
    expect(described_class.name).to eq('Msf::Module::Target')
  end

  describe 'inheriting module platforms' do
    it 'inherits the module platform before inferring versions' do
      mod = Msf::Exploit.new('Platform' => 'win', 'Targets' => [['Windows 7 SP1', {}]], 'DefaultTarget' => 0)
      mod.datastore['VERBOSE'] = true
      expect(mod.targets.first.platform.platforms).to eq([Msf::Module::Platform::Windows])
      expect(mod.targets.first.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP1)
    end

    it 'does not infer Windows versions for an inherited Linux platform' do
      mod = Msf::Exploit.new('Platform' => 'linux', 'Targets' => [['Windows 7 SP1', {}]], 'DefaultTarget' => 0)
      mod.datastore['VERBOSE'] = true
      expect(mod.targets.first.platform_versions).to be_nil
    end

    it 'preserves explicit target platforms and uses the original module platform for other targets' do
      mod = Msf::Exploit.new(
        'Platform' => 'win', 'DefaultTarget' => 0,
        'Targets' => [['Windows 7 SP1', { 'Platform' => 'linux' }], ['Windows 7 SP1', {}]]
      )
      mod.datastore['VERBOSE'] = true
      expect(mod.targets.first.platform.platforms).to eq([Msf::Module::Platform::Linux])
      expect(mod.targets.first.platform_versions).to be_nil
      expect(mod.targets.last.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP1)
    end

    it 'uses normalized platform classes as well as string declarations' do
      target = described_class.new('Windows 7 SP1', { 'Platform' => [Msf::Module::Platform::Windows, Msf::Module::Platform::Python] })
      expect(target.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP1)
    end

    it 'inherits platforms for evasion targets as well as exploit targets' do
      mod = Msf::Evasion.new('Platform' => 'win', 'Targets' => [['Windows 7 SP1', {}]], 'DefaultTarget' => 0)
      mod.datastore['VERBOSE'] = true
      expect(mod.targets.first.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP1)
    end

    it 'waits for a declared or inherited platform before inferring versions' do
      target = described_class.new('Windows 7 SP1', {})
      expect(target.platform_versions).to be_nil
      target.inherit_platform('linux')
      expect(target.platform_versions).to be_nil
    end
  end

  describe 'automatic platform version tagging' do
    subject(:target) { described_class.new(name, { 'Platform' => 'win' }.merge(opts)) }

    let(:opts) { {} }

    context 'when the name specifies a single Windows version' do
      let(:name) { 'Windows 7 SP1' }

      it 'infers the Windows platform version' do
        expect(target.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP1)
      end
    end

    context 'when the name is generic' do
      let(:name) { 'Windows x64' }

      it 'leaves the target untagged' do
        expect(target.platform_versions).to be_nil
      end
    end

    context 'when the name references several versions' do
      let(:name) { 'Windows XP SP3 / Windows 7 SP1' }

      it 'leaves the target untagged' do
        expect(target.platform_versions).to be_nil
      end
    end

    context 'when a Windows version is set manually' do
      let(:name) { 'Windows 7 SP1' }
      let(:opts) { { 'PlatformVersions' => { 'win' => Msf::WindowsVersion::XP_SP2 } } }

      it 'preserves the manual value' do
        expect(target.platform_versions).to eq('win' => Msf::WindowsVersion::XP_SP2)
      end
    end

    context 'when other platform versions are set manually' do
      let(:name) { 'Windows 7 SP1' }
      let(:opts) { { 'PlatformVersions' => { 'python' => '3.6' } } }

      it 'adds the inferred Windows version alongside them' do
        expect(target.platform_versions).to eq(
          'python' => '3.6',
          'win' => Msf::WindowsVersion::Win7_SP1
        )
      end
    end

    context 'when the target platform is not Windows' do
      let(:name) { 'Windows Server 2016' }
      let(:opts) { { 'Platform' => 'linux' } }

      it 'does not infer a Windows version' do
        expect(target.platform_versions).to be_nil
      end
    end

    context 'when the target platform is Windows' do
      let(:name) { 'Windows 7' }
      let(:opts) { { 'Platform' => 'win' } }

      it 'infers the Windows platform version' do
        expect(target.platform_versions).to eq('win' => Msf::WindowsVersion::Win7_SP0)
      end
    end
  end
end
