require 'spec_helper'

RSpec.describe Msf::Ui::Console::CommandDispatcher::Core do
  include_context 'Msf::Simple::Framework'
  include_context 'Msf::UIDriver'

  subject(:core) { described_class.new(driver) }

  let(:old_payload_name) { 'windows/x64/meterpreter/reverse_tcp' }
  let(:replacement_name) { 'windows/shell/reverse_tcp' }
  let(:replacement) { instance_double(Msf::Payload, platform_versions: platform_versions) }
  let(:platform_versions) { nil }
  let(:mod) do
    Msf::Exploit.new(
      'Name' => 'Target selection test',
      'Platform' => 'win',
      'Targets' => [['Windows 2000', {}]],
      'DefaultTarget' => 0
    ).tap do |instance|
      instance.datastore['VERBOSE'] = true
      instance.datastore['PAYLOAD'] = old_payload_name
      allow(instance).to receive(:framework).and_return(framework)
      allow(instance).to receive(:compatible_payloads).and_return([[replacement_name, nil]])
    end
  end

  before do
    allow(core).to receive(:active_module).and_return(mod)
    allow(driver).to receive(:on_variable_set).and_return(true)
    allow(Msf::Payload).to receive(:choose_payload).with(mod) do
      mod.datastore['PAYLOAD'] = replacement_name
      replacement_name
    end
    allow(framework.payloads).to receive(:create).and_return(nil)
    allow(framework.payloads).to receive(:create).with(replacement_name).and_return(replacement)
  end

  it 'checks the replacement payload after changing targets' do
    expect(mod).to receive(:version_compatibility_warnings).with(replacement).and_call_original

    core.cmd_set('TARGET', '0')

    expect(mod.datastore['PAYLOAD']).to eq(replacement_name)
    expect(@error || []).to be_empty
  end

  context 'when the replacement has incompatible version requirements' do
    let(:platform_versions) do
      { 'win' => [Msf::Module::VersionRange.new(min: Msf::WindowsVersion::XP_SP2)] }
    end

    it 'reports the replacement requirements' do
      core.cmd_set('TARGET', '0')

      expect(@error.join).to include('versions >= Windows XP Service Pack 2')
    end
  end

  context 'when no payload was previously selected' do
    let(:old_payload_name) { nil }

    it 'checks the newly selected payload' do
      expect(mod).to receive(:version_compatibility_warnings).with(replacement).and_call_original

      core.cmd_set('TARGET', '0')

      expect(mod.datastore['PAYLOAD']).to eq(replacement_name)
    end
  end
end
