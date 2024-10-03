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
