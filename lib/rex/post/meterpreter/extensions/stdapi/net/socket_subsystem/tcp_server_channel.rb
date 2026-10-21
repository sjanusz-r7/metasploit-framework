# -*- coding: binary -*-
require 'thread'
require 'rex/socket/parameters'
require 'rex/post/meterpreter/channels/stream'
require 'rex/post/meterpreter/extensions/stdapi/tlv'
require 'rex/post/meterpreter/extensions/stdapi/net/socket_subsystem/tcp_client_channel'

module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Net
module SocketSubsystem

class TcpServerChannel < Rex::Post::Meterpreter::Channel

  include Rex::IO::StreamServer

  # Keep the pending accept backlog bounded so an unconsumed remote listener
  # cannot create an unlimited number of local socket pairs.
  MAX_PENDING_ACCEPTS = 128

  #
  # This is the request handler which is registered to the respective meterpreter instance via
  # Rex::Post::Meterpreter::Extensions::Stdapi::Net::Socket. All incoming requests from the meterpreter
  # for a COMMAND_ID_STDAPI_NET_TCP_CHANNEL_OPEN will be processed here. We create a new TcpClientChannel for each request
  # received and store it in the respective tcp server channels list of new pending client channels.
  # These new tcp client channels are passed off via a call the tcp server channels accept() method.
  #
  def self.request_handler(client, packet)
    return false unless packet.method == COMMAND_ID_STDAPI_NET_TCP_CHANNEL_OPEN

    cid = packet.get_tlv_value(TLV_TYPE_CHANNEL_ID)
    pid = packet.get_tlv_value(TLV_TYPE_CHANNEL_PARENTID)

    return false if cid.nil? || pid.nil?

    server_channel = client.find_channel(pid)

    return false if server_channel.nil?

    unless server_channel.pending_accept_available?
      reject_remote_client(client, cid)
      return true
    end

    params = Rex::Socket::Parameters.from_hash(
      {
        'Proto' => 'tcp',
        'Comm' => server_channel.client
      }
    )

    client_channel = TcpClientChannel.new(client, cid, TcpClientChannel, CHANNEL_FLAG_SYNCHRONOUS, packet, sock_params: params)
    ilog("enqueueing new TCP client with channel id #{cid}")

    unless server_channel.enqueue_pending_client(client_channel)
      server_channel.schedule_pending_client_cleanup([client_channel])
    end

    true
  end

  def self.reject_remote_client(client, cid)
    request = Packet.create_request(COMMAND_ID_CORE_CHANNEL_CLOSE)
    request.add_tlv(TLV_TYPE_CHANNEL_ID, cid)
    client.send_packet(request)
  rescue StandardError => e
    elog("Failed to reject pending TCP client channel #{cid}", error: e)
  end
  private_class_method :reject_remote_client

  def self.cls
    CHANNEL_CLASS_STREAM
  end

  #
  # Open a new tcp server channel on the remote end.
  #
  # @return [Channel]
  def self.open(client, params)
    Channel.create(client, 'stdapi_net_tcp_server', self, CHANNEL_FLAG_SYNCHRONOUS,
      [
        { 'type' => TLV_TYPE_LOCAL_HOST, 'value' => params.localhost },
        { 'type' => TLV_TYPE_LOCAL_PORT, 'value' => params.localport }
      ],
      sock_params: params
    )
  end

  #
  # Simply initialize this instance.
  #
  def initialize(client, cid, type, flags, packet, sock_params: nil)
    # Initialize the queue before registering the channel so an inbound open
    # cannot observe a server without a pending-accept queue.
    @pending_accepts = ::SizedQueue.new(MAX_PENDING_ACCEPTS)
    super(client, cid, type, flags, packet)

    unless sock_params.nil?
      @params = sock_params.merge(Socket.parameters_from_response(packet))
      if sock_params.ssl
        extend(Rex::Socket::SslTcpServer)
        initsock(sock_params)
      end
    end
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method does not block
  # and returns nil if no new client connection is available.
  #
  def accept_nonblock
    _accept(nonblock: true)
  end

  #
  # Accept a new tcp client connection form this tcp server channel. This method will block indefinitely
  # if no timeout is specified.
  #
  def accept(opts = {})
    timeout = opts['Timeout']
    if timeout.nil? || timeout <= 0
      timeout = nil
    end

    _accept(timeout: timeout)
  end

  def pending_accept_available?
    !@pending_accepts.closed? && @pending_accepts.length < @pending_accepts.max
  end

  def enqueue_pending_client(channel)
    @pending_accepts.push(channel, true)
    true
  rescue ThreadError, ClosedQueueError
    false
  end

  def schedule_pending_client_cleanup(channels)
    return if channels.empty?

    cleanup_task = proc do
      channels.each { |channel| close_pending_client(channel) }
    end
    client.framework.sessions.schedule(cleanup_task)
  rescue StandardError => e
    elog('Failed to schedule pending TCP client cleanup', error: e)
    cleanup_task&.call
  end

protected

  # Uses Queue#deq(timeout:) instead of ::Timeout.timeout to avoid
  # GVL contention causing missed connections in Ruby 3.x
  def _accept(nonblock: false, timeout: nil)
    result = nil

    begin
      if nonblock
        channel = @pending_accepts.deq(true)
      elsif timeout
        channel = @pending_accepts.deq(timeout: timeout)
      else
        channel = @pending_accepts.deq
      end

      if channel
        result = channel.lsock
      end

      if !result.nil? && !result.is_a?(Rex::Socket::Tcp)
        result.extend(Rex::Socket::Tcp)
      end
    rescue ThreadError
      # No clients in queue (nonblock mode)
    end

    result
  end

  def _close(addends = nil)
    super
  ensure
    cleanup
  end

  def cleanup
    pending_clients = drain_pending_clients
    schedule_pending_client_cleanup(pending_clients)
    super
  end

  def drain_pending_clients
    pending_clients = []
    @pending_accepts.close

    loop do
      channel = @pending_accepts.pop(true)
      break unless channel

      pending_clients << channel
    end
  rescue ThreadError
    pending_clients
  end

  def close_pending_client(channel)
    channel_id = channel.cid

    begin
      channel.close
    rescue IOError
      nil
    rescue StandardError => e
      elog("Failed to close pending TCP client channel #{channel_id}", error: e)
    ensure
      unless channel.closed?
        ObjectSpace.undefine_finalizer(channel)
        channel.send(:cid=, nil)
        channel.client.remove_channel(channel_id)
      end

      begin
        channel.send(:cleanup)
      rescue IOError
        nil
      rescue StandardError => e
        elog("Failed to clean up pending TCP client channel #{channel_id}", error: e)
      end
    end
  end

end

end; end; end; end; end; end; end
