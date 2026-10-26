# -*- coding: binary -*-
# frozen_string_literal: true

module Msf::Sessions
  #
  # Shared output-buffering and polling logic for the WinRM stream adapters
  # (Msf::Sessions::WinrmCommandShell::WinRMStreamAdapter and
  # Msf::Sessions::WinrmPowerShell::WinRMPowerShellStreamAdapter). Both
  # adapters receive output on a background thread and buffer it for
  # Msf::Session::Provider::SingleCommandShell to read via #get_once.
  #
  module WinrmStreamAdapterCommon
    # Default maximum buffer size in bytes. Matches Output::Buffer's default.
    DEFAULT_MAX_BUFFER_BYTES = 4 * 1024 * 1024

    TRUNCATION_MARKER = "[truncated: buffer exceeded byte limit]\n"

    # Includers must call this from #initialize before using #get_once,
    # #_get_once, or #append_output.
    def init_stream_buffer
      @buffer_mutex = Mutex.new
      @buffer = []
      @buffer_bytesize = 0
      @buffer_truncated = false
      # auto_reset is false: #get_once resets the event itself after every
      # wake-up, immediately before it re-checks the buffer. If the event
      # auto-reset on #set instead, a #set landing between that buffer check
      # and the call to #wait would be missed (a classic lost wakeup),
      # leaving the reader blocked for the full timeout even though output
      # was already sitting in the buffer.
      @received_stdout_event = Rex::Sync::Event.new(false, false)
    end

    def peerinfo
      shell.transport.peerinfo
    end

    def localinfo
      shell.transport.localinfo
    end

    ##
    # :category: Msf::Session::Provider::SingleCommandShell implementors
    #
    # Read buffered output received from the background thread. Yields
    # (if a block is given) each time we're about to loop back and wait
    # again, so includers can nudge their background thread along.
    #
    def get_once(length = -1, timeout = 1)
      start_time = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      result = ''
      loop do
        result = _get_once(length)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_time
        time_remaining = timeout - elapsed
        break if result != '' || time_remaining <= 0

        # rubocop:disable Lint/SuppressedException
        begin
          @received_stdout_event.wait(time_remaining)
        rescue ::Timeout::Error
        ensure
          @received_stdout_event.reset
        end
        # rubocop:enable Lint/SuppressedException
        yield if block_given?
      end
      result
    end

    def _get_once(length)
      result = ''
      @buffer_mutex.synchronize do
        result = @buffer.join('')
        @buffer = []
        @buffer_bytesize = 0
        @buffer_truncated = false
        if (length > -1) && (result.length > length)
          # Return up to length, and keep the rest in the buffer.
          extra = result[length..]
          result = result[0, length]
          @buffer << extra
          @buffer_bytesize = extra.bytesize
        end
      end
      result
    end

    private

    # Called under @buffer_mutex after new entries have been appended.
    # Trims from the front of @buffer to enforce the byte cap.
    def enforce_stream_buffer_limit
      return if @buffer_bytesize <= DEFAULT_MAX_BUFFER_BYTES

      trimmed = 0
      while @buffer_bytesize - trimmed > DEFAULT_MAX_BUFFER_BYTES && !@buffer.empty?
        trimmed += @buffer.shift.bytesize
      end
      @buffer_bytesize -= trimmed

      unless @buffer_truncated
        @buffer.unshift(TRUNCATION_MARKER)
        @buffer_bytesize += TRUNCATION_MARKER.bytesize
        @buffer_truncated = true
      end
    end
  end
end
