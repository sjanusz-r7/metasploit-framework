require 'spec_helper'

RSpec.describe Msf::Payload::Python::MeterpreterLoader do
  subject(:payload) do
    Class.new(Msf::Payload) do
      include Msf::Payload::Python::MeterpreterLoader
    end.new
  end

  describe 'supported Python versions' do
    %w[2.5 2.7 2.7.0 2.7.18 3.1 3.13].each do |version|
      it "supports Python #{version}" do
        expect(payload.platform_versions['python'].any? { |range| range.contains?(version) }).to be true
      end
    end

    %w[2.4 3.0 3.0.0 3.0.1].each do |version|
      it "rejects Python #{version}" do
        expect(payload.platform_versions['python'].any? { |range| range.contains?(version) }).to be false
      end
    end
  end
end
