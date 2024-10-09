require 'reline'

::Encoding.default_external = ::Encoding::ASCII_8BIT
::Encoding.default_internal = ::Encoding::ASCII_8BIT

# Workaround to fix:
class ::Reline::ANSI
  def encoding
    ::Encoding::UTF_8
  end
end

ascii_text = Reline.readline('prompt > ', false)

$stderr.puts ascii_text.encoding.to_s
