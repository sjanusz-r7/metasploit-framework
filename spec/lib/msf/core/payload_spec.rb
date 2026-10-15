# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/payload'

RSpec.describe Msf::Payload do
  let(:klass) { Class.new(described_class) }

  describe '.choose_payload' do
    let(:datastore) { { 'LHOST' => '192.0.2.1', 'VERBOSE' => true } }
    let(:payloads) { double('Payload modules') }
    let(:framework) { double('Framework', payloads: payloads) }
    let(:mod) { double('Exploit', datastore: datastore, framework: framework) }
    let(:unsupported) { instance_double(Msf::Payload) }
    let(:supported) { instance_double(Msf::Payload) }

    before do
      allow(mod).to receive(:compatible_payloads).with(excluded_platforms: ['Multi']).and_return(names.map { |name| [name, nil] })
      allow(mod).to receive(:version_compatibility_warnings).with(unsupported).and_return(['Unsupported version'])
      allow(mod).to receive(:version_compatibility_warnings).with(supported).and_return([])
    end

    context 'when the only payload has an unsupported version' do
      let(:names) { ['windows/meterpreter/reverse_tcp'] }

      before do
        allow(payloads).to receive(:create).with(names.first).and_return(unsupported)
      end

      it 'leaves the payload unset' do
        expect(described_class.choose_payload(mod)).to be_nil
        expect(datastore).not_to have_key('PAYLOAD')
      end
    end

    context 'when the only payload supports the target version' do
      let(:names) { ['windows/meterpreter/reverse_tcp'] }

      before do
        allow(payloads).to receive(:create).with(names.first).and_return(supported)
      end

      it 'selects and configures it' do
        expect(described_class.choose_payload(mod)).to eq(names.first)
        expect(datastore['PAYLOAD']).to eq(names.first)
      end
    end

    context 'when candidates share a preferred suffix' do
      let(:names) { %w[python/meterpreter/reverse_tcp java/meterpreter/reverse_tcp] }

      before do
        allow(payloads).to receive(:create).with(names.first).and_return(unsupported)
        allow(payloads).to receive(:create).with(names.last).and_return(supported)
      end

      it 'tries the next matching payload after rejecting the first' do
        expect(described_class.choose_payload(mod)).to eq(names.last)
        expect(datastore['PAYLOAD']).to eq(names.last)
      end
    end

    context 'when a payload cannot be instantiated' do
      let(:names) { %w[python/meterpreter/reverse_tcp java/meterpreter/reverse_tcp] }

      before do
        allow(payloads).to receive(:create).with(names.first).and_return(nil)
        allow(payloads).to receive(:create).with(names.last).and_return(supported)
      end

      it 'continues to the next matching payload' do
        expect(described_class.choose_payload(mod)).to eq(names.last)
      end
    end
  end

  describe '.cached_size' do
    context 'when CachedSize is not defined' do
      it 'returns nil' do
        expect(klass.cached_size).to be_nil
      end
    end

    context 'when CachedSize is defined as an integer' do
      let(:klass) do
        Class.new(described_class).tap do |klass|
          klass.const_set(:CachedSize, 123)
        end
      end

      it 'returns the integer value' do
        expect(klass.cached_size).to eq(123)
      end
    end

    context 'when CachedSize is defined as :dynamic' do
      let(:klass) do
        Class.new(described_class).tap do |klass|
          klass.const_set(:CachedSize, :dynamic)
        end
      end

      it 'returns nil' do
        expect(klass.cached_size).to be_nil
      end
    end

    context 'when class is a Stager and CachedSizeOverrides is defined' do
      let(:stager_klass) do
        Class.new(described_class).tap do |klass|
          klass.send(:include, Msf::Payload::Stager)
          klass.const_set(:CachedSize, 111)
          klass.const_set(:CachedSizeOverrides, { 'windows/stage/stager' => 222 })
          klass.define_singleton_method(:refname) { 'windows/stage/stager' }
        end
      end

      it 'returns the override value for the stager refname' do
        expect(stager_klass.cached_size).to eq(222)
      end
    end
  end

  describe '#cached_size' do
    it 'delegates to .cached_size' do
      obj = klass.new
      allow(klass).to receive(:cached_size).and_return(42)
      expect(obj.cached_size).to eq(42)
    end
  end
end
