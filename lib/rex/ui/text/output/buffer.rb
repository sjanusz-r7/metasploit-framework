# -*- coding: binary -*-

module Rex
module Ui
module Text

###
#
# This class implements output against a buffer.
#
###
class Output::Buffer < Rex::Ui::Text::Output

  # Default maximum buffer size in bytes. 4 MB is generous for any interactive
  # display while preventing unbounded growth from backgrounded sessions or
  # stalled consumers.
  DEFAULT_MAX_BUFFER_BYTES = 4 * 1024 * 1024

  TRUNCATION_MARKER = "[truncated: buffer exceeded byte limit]\n"

  #
  # Initializes an output buffer.
  #
  # @param max_bytes [Integer] Maximum buffer size in bytes. When appending
  #   would exceed this limit, the oldest content is discarded. Pass 0 to
  #   disable the cap.
  #
  def initialize(max_bytes: DEFAULT_MAX_BUFFER_BYTES)
    self.buf = ''
    @max_bytes = max_bytes
    @truncated = false
  end

  def supports_color?
    false
  end

  #
  # Appends the supplied message to the output buffer. If the buffer would
  # exceed max_bytes, the oldest content is discarded and a one-time
  # truncation marker is prepended.
  #
  def print_raw(msg = '')
    self.buf += msg || ''
    enforce_byte_limit
    msg
  end


  #
  # Read everything out of the buffer and reset it
  #
  def dump_buffer
    self.buf ||= ''
    buffer = self.buf.dup
    reset()
    buffer
  end

  #
  # Reset the buffer to an empty string.
  #
  def reset
    self.buf = ''
  end

  #
  # The underlying buffer state.
  #
  attr_accessor :buf

  private

  def enforce_byte_limit
    return if @max_bytes <= 0
    return if self.buf.bytesize <= @max_bytes

    # Trim from the front to keep the most recent output
    excess = self.buf.bytesize - @max_bytes
    self.buf = self.buf.byteslice(excess..)

    # Always prepend the marker after trimming so the reader sees it
    # regardless of how many overflows have occurred.
    self.buf = TRUNCATION_MARKER + self.buf unless self.buf.start_with?(TRUNCATION_MARKER)
  end

end

end
end
end
