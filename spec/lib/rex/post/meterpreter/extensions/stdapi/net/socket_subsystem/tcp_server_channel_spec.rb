# frozen_string_literal: true

require 'spec_helper'
require 'rex/socket'
require 'rex/post/meterpreter/packet'
require 'rex/post/meterpreter/extensions/stdapi/command_ids'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/tcp_server_channel'

RSpec.describe Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::TcpServerChannel do
  let(:session_manager) { double('session_manager') }
  let(:framework) { double('framework', sessions: session_manager) }
  let(:client) do
    double(
      'client',
      add_channel: nil,
      find_channel: nil,
      framework: framework,
      remove_channel: nil,
      send_packet: nil,
      send_request: nil
    )
  end
  let(:server_channel) do
    described_class.new(
      client,
      1,
      described_class,
      Rex::Post::Meterpreter::CHANNEL_FLAG_SYNCHRONOUS,
      nil
    )
  end
  let(:local_socket) do
    double('local_socket').tap do |socket|
      allow(socket).to receive(:is_a?).with(Rex::Socket::Tcp).and_return(true)
    end
  end
  let(:pending_client) do
    double(
      'pending_client',
      cid: 2,
      cleanup: nil,
      close: true,
      closed?: true,
      lsock: local_socket
    )
  end

  before do
    # rubocop:disable Style/SymbolProc
    allow(session_manager).to receive(:schedule) { |task| task.call }
    # rubocop:enable Style/SymbolProc
  end

  after do
    ObjectSpace.undefine_finalizer(server_channel)
  end

  describe '#accept' do
    it 'returns nil when the timeout expires' do
      expect(server_channel.accept('Timeout' => 0.01)).to be_nil
    end

    it 'returns the local socket for a pending client' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)

      expect(server_channel.accept('Timeout' => 1)).to eq(local_socket)
    end

    it 'wakes a blocked accept when the server is cleaned up' do
      accept_thread = Thread.new { server_channel.accept }
      sleep 0.05

      server_channel.send(:cleanup)

      expect(accept_thread.join(2)).to eq(accept_thread)
      expect(accept_thread.value).to be_nil
    end
  end

  describe '#accept_nonblock' do
    it 'returns nil when no client is pending' do
      expect(server_channel.accept_nonblock).to be_nil
    end

    it 'returns the local socket for a pending client' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)

      expect(server_channel.accept_nonblock).to eq(local_socket)
    end
  end

  describe '#enqueue_pending_client' do
    before do
      server_channel.instance_variable_set(:@pending_accepts, SizedQueue.new(1))
    end

    it 'rejects clients once the pending accept queue is full' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)
      expect(server_channel.enqueue_pending_client(double('overflow_client'))).to be(false)
    end

    it 'rejects clients after the server is closed' do
      server_channel.send(:cleanup)

      expect(server_channel.enqueue_pending_client(pending_client)).to be(false)
    end
  end

  describe '.request_handler' do
    let(:packet) do
      double('packet', method: Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_NET_TCP_CHANNEL_OPEN)
    end

    before do
      allow(packet).to receive(:get_tlv_value)
        .with(Rex::Post::Meterpreter::TLV_TYPE_CHANNEL_ID).and_return(2)
      allow(packet).to receive(:get_tlv_value)
        .with(Rex::Post::Meterpreter::TLV_TYPE_CHANNEL_PARENTID).and_return(1)
      allow(client).to receive(:find_channel).with(1).and_return(server_channel)
      server_channel.instance_variable_set(:@pending_accepts, SizedQueue.new(1))
      server_channel.enqueue_pending_client(pending_client)
    end

    it 'rejects overflow before allocating another local socket pair' do
      expect(Rex::Post::Meterpreter::Extensions::Stdapi::Net::SocketSubsystem::TcpClientChannel)
        .not_to receive(:new)
      expect(client).to receive(:send_packet)
        .with(instance_of(Rex::Post::Meterpreter::Packet))

      expect(described_class.request_handler(client, packet)).to be(true)
    end
  end

  describe 'cleanup' do
    it 'drains and closes pending clients on local close' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)
      expect(pending_client).to receive(:close).once
      expect(pending_client).to receive(:cleanup).once

      server_channel.close

      expect(server_channel.enqueue_pending_client(double('late_client'))).to be(false)
    end

    it 'drains and closes pending clients on remote close' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)
      expect(pending_client).to receive(:close).once
      expect(pending_client).to receive(:cleanup).once

      server_channel.dio_close_handler(nil)

      expect(server_channel.enqueue_pending_client(double('late_client'))).to be(false)
    end

    it 'does not close clients which have already been accepted' do
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)
      expect(server_channel.accept_nonblock).to eq(local_socket)
      expect(pending_client).not_to receive(:close)

      server_channel.close
    end

    it 'continues draining after a pending client close fails' do
      failed_client = double(
        'failed_client',
        cid: 3,
        cleanup: nil,
        client: client,
        close: nil,
        closed?: false,
        :cid= => nil
      )
      allow(failed_client).to receive(:close)
        .and_raise(Rex::ConnectionError, 'Connection closed')
      allow(server_channel).to receive(:elog)
      expect(server_channel.enqueue_pending_client(failed_client)).to be(true)
      expect(server_channel.enqueue_pending_client(pending_client)).to be(true)
      expect(pending_client).to receive(:close).once

      server_channel.send(:cleanup)

      expect(client).to have_received(:remove_channel).with(3)
      expect(failed_client).to have_received(:cleanup)
    end
  end
end
