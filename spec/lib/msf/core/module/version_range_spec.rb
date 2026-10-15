# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Module::VersionRange do
  describe '.valid_version_value?' do
    [
      { value: nil, expected: false },
      { value: 'nil', expected: false },
      { value: '', expected: false },
      { value: 0, expected: true },
      { value: '0', expected: true },
      { value: false, expected: false },
      { value: true, expected: false },
      { value: {}, expected: false },
      { value: [], expected: false },
      { value: [{}], expected: false },
      { value: '0.0.1', expected: true },
      { value: '1.0.0', expected: true },
      { value: '1.0.0.0', expected: true },
    ].each do |test_case|
      context "when provided with #{test_case[:value].inspect}" do
        it "returns #{test_case[:expected]}" do
          expect(described_class.valid_version_value?(test_case[:value])).to eq(test_case[:expected])
        end
      end
    end
  end

  describe '#initialize' do
    context 'when min is nil' do
      it 'preserves the unbounded minimum' do
        expect(described_class.new(max: '1.0.0').min).to be_nil
      end
    end

    context 'when min is an invalid string' do
      it 'raises an error' do
        expect { described_class.new(min: 'nil', max: '1.0.0') }.to raise_error(ArgumentError, /Invalid minimum/)
      end
    end

    context 'when both min and max are valid' do
      it 'does not raise' do
        expect { described_class.new(min: '1.0.0', max: '2.0.0') }.not_to raise_error
      end
    end

    context 'when max is nil (unbounded range)' do
      it 'does not raise' do
        expect { described_class.new(min: '1.0.0') }.not_to raise_error
      end

      it 'stores nil max' do
        range = described_class.new(min: '1.0.0')
        expect(range.max).to be_nil
      end
    end
  end

  describe '#contains?' do
    context 'with only a maximum' do
      it 'includes versions up to and including the maximum' do
        range = described_class.new(max: '1.2.20')
        expect(range.contains?('0')).to be true
        expect(range.contains?('1.2.20')).to be true
        expect(range.contains?('1.2.21')).to be false
      end

      it 'honors an exclusive maximum without a minimum' do
        range = described_class.new(max: '3.0', exclude_max: true)
        expect(range.contains?('2.7.18')).to be true
        expect(range.contains?('3.0')).to be false
      end
    end

    it 'accepts any valid version when neither bound is set' do
      range = described_class.new
      expect(range.contains?('0')).to be true
      expect(range.contains?('999')).to be true
      expect(range.contains?(nil)).to be_nil
    end

    context 'with an exclusive maximum' do
      subject(:range) { described_class.new(min: '2.5', max: '3.0', exclude_max: true) }

      %w[2.5 2.7 2.7.0 2.7.18].each do |version|
        it "includes #{version}" do
          expect(range.contains?(version)).to be true
        end
      end

      %w[2.4 3.0 3.0.0 3.0.1].each do |version|
        it "excludes #{version}" do
          expect(range.contains?(version)).to be false
        end
      end
    end

    [
      # bounded range
      { min: '0.0.0', max: '1.0.0', value: nil, expected: nil },
      { min: '0.0.0', max: '1.0.0', value: 'nil', expected: nil },
      { min: '0.0.0', max: '1.0.0', value: '1.0.0', expected: true },
      { min: '0.0.0', max: '1.0.0', value: '0.5.0', expected: true },
      { min: '0.0.0', max: '1.0.0', value: '1.0.1', expected: false },
      { min: '0.0.0', max: '1.0.0', value: 0, expected: true },
      { min: '0.0.0', max: '1.0.0', value: 1, expected: true },
      { min: '0.0.0', max: '1.0.0', value: 5, expected: false },
      # unbounded range (no max)
      { min: '1.0.0', max: nil, value: '0.9.0', expected: false },
      { min: '1.0.0', max: nil, value: '1.0.0', expected: true },
      { min: '1.0.0', max: nil, value: '99.0.0', expected: true },
      # boundary conditions
      { min: '2.5', max: '2.7', value: '2.4', expected: false },
      { min: '2.5', max: '2.7', value: '2.5', expected: true },
      { min: '2.5', max: '2.7', value: '2.6', expected: true },
      { min: '2.5', max: '2.7', value: '2.7', expected: true },
      { min: '2.5', max: '2.7', value: '3.0', expected: false },
    ].each do |test_case|
      context "with range #{test_case[:min]}..#{test_case[:max] || '∞'}" do
        it "returns #{test_case[:expected].inspect} for value #{test_case[:value].inspect}" do
          subject = described_class.new(min: test_case[:min], max: test_case[:max])
          expect(subject.contains?(test_case[:value])).to eq(test_case[:expected])
        end
      end
    end
  end

  describe '#description' do
    it 'describes a maximum without inventing a minimum' do
      expect(described_class.new(max: '1.2.20').description).to eq('<= 1.2.20')
    end

    it 'describes an unconstrained range' do
      expect(described_class.new.description).to eq('any version')
    end

    it 'rejects inverted bounds' do
      expect { described_class.new(min: '3', max: '2') }.to raise_error(ArgumentError, /precedes/)
    end
  end
end
