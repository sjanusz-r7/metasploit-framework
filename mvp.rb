<<<<<<< Updated upstream
# TODO: Make a pull request for this
require 'reline'
class ::Reline::ANSI
  def encoding
    ::Encoding::UTF_8
  end
end
#
class ::Reline::Core

  alias old_completion_append_character= completion_append_character=
  alias old_completion_append_character completion_append_character

  def completion_append_character=(v)
    # require 'pry-byebug'; binding.pry
    self.old_completion_append_character=(v)
    # Additionally keep the line_editor in sync
    line_editor.completion_append_character = self.old_completion_append_character
  end
end

begin
  while true
    text = Reline.readmultiline(prompt, use_history) do |multiline_input|
      # Accept the input until `end` is entered
      multiline_input.split.last == "end"
    end

    puts 'You entered:'
    puts text
  end
  # If you want to exit, type Ctrl-C
rescue Interrupt
  puts '^C'
  exit 0
end

# TODO:

# 1. MVP replication for the module tab completion bug, i.e. we shouldn't be appending the tab completion char if we still have completion values left?
# 1. MVP Replication for showing that we need this hack to work:
=======
require 'reline'
require 'concurrent'

# TODO:
# 1. MVP replication for the module tab completion bug, i.e. we shouldn't be appending the tab completion char if we still have completion values left?
# 2. MVP Replication for showing that we need this hack to work:
>>>>>>> Stashed changes
#       Reline.dig_perfect_match_proc = ->(_matched) do
#         Reline.line_editor.instance_variable_set(:@completion_state, Reline::LineEditor::CompletionState::MENU_WITH_PERFECT_MATCH)
#       end
#      i.e. the scenario of `run lhos<tab>` and then `run lhost=<tab><tab>` should show us the auto complete values
# 3. MVP replication for the encoding scenario of our common engine setting encoding to ascii-8bit, but we want reline to be utf-8
#     config.before_initialize do
#       encoding = 'binary'
#       ::Encoding.default_external = encoding
#       ::Encoding.default_internal = encoding
#     end
# 4. MVP Showing printing out async can mess up the formatting
<<<<<<< Updated upstream
=======

## 1. Tab completion bug where we append spaces after auto-completion, as opposed to only appending it once no results from the
# tab completion proc are returned.
# module TABCOMPLETE
#   COMPLETION_VALUES = ['my_dir/http/linux/apache', 'my_dir/http/linux/ngnix', 'my_dir/windows/chrome', 'my_dir/linux/enum'].freeze
#
#   tab_complete_lambda = proc do |_str, _preposing = nil, _postposing = nil|
#     COMPLETION_VALUES
#   end
#
#   begin
#     prompt = 'Prompt > '
#     use_history = false
#     getting_input = true
#
#     Reline.completion_append_character = ' '
#     Reline.completion_proc = tab_complete_lambda
#
#     while getting_input
#       text = Reline.readmultiline(prompt, use_history) do |multiline_input|
#         # Accept the input until 'end' is entered
#         multiline_input.split.last == 'end'
#       end
#
#       getting_input = false
#       puts 'You entered:'
#       puts text
#     end
#     # If you want to exit, type Ctrl-C
#   rescue Interrupt
#     puts '^C'
#   end
# end

## 2. Needing to set the completion state to receive completion values after pressing TAB
module MATCHPROC
  COMPLETION_OPTS = ['RHOST=', 'PAYLOAD='].freeze
  COMPLETION_VALUES = ['127.0.0.1', 'exploit/windows/xyz'].freeze

  def self.log(msg = '')
    File.open('test_file.log', 'a') do |file| file.write(msg) end
  end

  def self.suggestion(str, preposing = nil, postposing = nil)
    log("Completion State: #{Reline.line_editor.instance_variable_get(:@completion_state)}\n")
    log("String: #{str}\n")
    log("Preposing: #{preposing}\n")

    result = []
    COMPLETION_OPTS.each do |opt|
      if opt.downcase.start_with?(str)
        result << opt.downcase
      end
    end

    COMPLETION_VALUES.each do |opt|
      if opt.downcase.start_with?(str)
        result << opt.downcase
      end
    end

    if str.casecmp?('rhost=')
      log('We are matching with rhost!')
      result << COMPLETION_VALUES[0]
    end
    if str.casecmp?('PAYLOAD=')
      log('We are matching with payload!')
      result << COMPLETION_VALUES[1]
    end

    result
  end

  tab_complete_lambda = proc do |str, preposing = nil, postposing = nil|
    next suggestion(str, preposing, postposing)
  end

  begin
    prompt = 'Prompt > '
    use_history = false
    getting_input = true

    Reline.completion_proc = tab_complete_lambda
    Reline.completion_case_fold = false

    # Reline.dig_perfect_match_proc = ->(_matched) do
    #   Reline.line_editor.instance_variable_set(:@completion_state, Reline::LineEditor::CompletionState::MENU_WITH_PERFECT_MATCH)
    # end

    while getting_input
      text = Reline.readmultiline(prompt, use_history) do |multiline_input|
        # Accept the input until 'end' is entered
        multiline_input.split.last == 'end'
      end

      getting_input = false
      puts 'You entered:'
      puts text
    end
    # If you want to exit, type Ctrl-C
  rescue Interrupt
    puts '^C'
  end
end

# 3. Allow for setting Reline's encoding
# module OWN_ENCODING
#
#
#   default_external_encoding = ::Encoding.default_external
#   default_internal_encoding = ::Encoding.default_internal
#   # 1. Begin with UTF-8 encoding as expected.
#   # 2. Overwrite the encoding to ASCII-8BIT
#   # 3. Allow for overwriting Reline's encoding using options or a setter
#   utf8_text = Reline.readline('hello utf8 > ', false)
#
#   $stderr.puts utf8_text.encoding.to_s
#
#
#
#   custom_encoding_text = Reline.readline('hello custom encoding > ', false)
#
#   $stderr.puts custom_encoding_text.encoding.to_s
#
#   ::Encoding.default_external = default_external_encoding
#   ::Encoding.default_internal = default_internal_encoding
# end

# class ::Reline::Core
#
#   alias old_completion_append_character= completion_append_character=
#   alias old_completion_append_character completion_append_character
#
#   def completion_append_character=(v)
#     # require 'pry-byebug'; binding.pry
#     self.old_completion_append_character=(v)
#     # Additionally keep the line_editor in sync
#     line_editor.completion_append_character = self.old_completion_append_character
#   end
# end

# 4. Add the ability to synchronize outputs
# Reline seems to get confused about where in the console to begin writing output.
# For example (No space?):
# [*] Using URL: http://10.5.135.201:8080/printers/hukW4Iiv4IB6Q8
#                                                                [*] Sending probes to 10.5.130.129->10.5.130.129 (1 hosts)
# Which is conveniently where the input ends... Or (with a space):
# [*] Started reverse TCP handler on 172.16.199.1:4444
#                                                      msf6 payload(linux/x64/meterpreter/reverse_tcp) >
# After pressing the enter key the spacing corrected itself.

# module ASYNC
#   pool = ::Concurrent::FixedThreadPool.new(4)
#
#   0..4.times do |i|
#     pool.post do |thread|
#       while true
#         $stdout.puts "Long message from thread #{i}..."
#         sleep(1)
#       end
#     end
#   end
#
#   text = ::Reline.readline('p > ', false)
# end

# 5. Keep the line editor completion_append_character in sync with Reline Core:
# This way, we can change the completion_append_character in a tab completion procedure without needing to go into
# a new Reline.readline/Reline.readmultiline method call.
# module COMPLETIONCHAR
#   def self.suggestion(str, preposing = nil, postposing = nil)
#     result = ['testing', 'else', 'option_1', 'option_2']
#
#     # Alternate between the completion characters
#     if Reline.completion_append_character == ' '
#       Reline.completion_append_character = ''
#     else
#       Reline.completion_append_character = ' '
#     end
#
#     result.select { |opt| opt.downcase.start_with?(str) }
#   end
#
#   tab_complete_lambda = proc do |str, preposing = nil, postposing = nil|
#     next suggestion(str, preposing, postposing)
#   end
#
#   Reline.completion_proc = tab_complete_lambda
#   _text = Reline.readline('hello_world > ', false)
#   _text_2 = Reline.readline('hello_world_2 > ', false)
#
#   class ::Reline::Core
#
#     alias old_completion_append_character= completion_append_character=
#     alias old_completion_append_character completion_append_character
#
#     def completion_append_character=(v)
#       self.old_completion_append_character=(v)
#       # Additionally keep the line_editor in sync
#       line_editor.completion_append_character = self.old_completion_append_character
#     end
#   end
#
#   # Changing the completion_append_character in the completion_proc works.
#   _text_3 = Reline.readline('hello_world > ', false)
# end
>>>>>>> Stashed changes
