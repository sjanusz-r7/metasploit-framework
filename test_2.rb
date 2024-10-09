require 'reline'

tab_complete_lambda = proc do |str_wip, preposing = nil, postposing = nil|
  $stderr.puts 'triggered'
  # require 'pry-byebug'; binding.pry;
  # require 'pry-byebug'; binding.pry;
  # str = "#{preposing}#{str}" if str && preposing
  if preposing.eql?('--option=')
    $stderr.puts 'here'
    require 'pry-byebug'; binding.pry;
    next ['value_1', 'value_2']
  end
  if str_wip&.start_with?('--option=')
    # ['--option=value_1'[preposing.length..]]

  elsif str_wip&.start_with?('--')
    ['--option=']
  else
    ['--option=value_1']
  end
end

prompt = 'Prompt > '
use_history = false

Reline.basic_word_break_characters = "\x00"
Reline.completion_proc = tab_complete_lambda
Reline.completion_case_fold = false

# Reline.dig_perfect_match_proc = ->(_matched) do
#   Reline.line_editor.instance_variable_set(:@completion_state, Reline::LineEditor::CompletionState::MENU_WITH_PERFECT_MATCH)
# end

_text = Reline.readline(prompt, use_history)
