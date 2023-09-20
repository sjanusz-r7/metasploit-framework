# -*- coding: binary -*-

require 'rex/post/postgresql'

class Msf::Sessions::PostgreSQL # < Msf::Sessions::CommandShell
  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  # @return [Rex::Post::PostgreSQL::Ui::Console] The interactive console
  attr_accessor :console
  # @return [PostgreSQL::Client]
  attr_accessor :client
  attr_accessor :platform
  attr_accessor :arch

  # ##@param [PostgreSQL::Client] client
  # @param [PostgreSQL::Client] rstream
  def initialize(rstream, opts={})
    @client = opts.fetch(:client)
    self.console = ::Rex::Post::PostgreSQL::Ui::Console.new(self)
    super(rstream, opts)
  end

  def bootstrap(datastore = {}, handler = nil)
    # this won't work after the rstream is initialized, so do it first
    # @platform = 'windows' # Metasploit::Framework::Ssh::Platform.get_platform(ssh_connection)
    # super

    session = self
    session.init_ui(self.user_input, self.user_output)

    @info = "PostgreSQL #{datastore['USERNAME']} @ #{@peer_info}"
  end

  def process_autoruns(datastore)
    # TODO - Implemented for now to keep things happy
  end

  def type
    self.class.type
  end

  #
  # @return [String] The type of the session
  #
  def self.type
    'PostgreSQL'
  end

  #
  # @return [Boolean] Can the session clean up after itself
  def self.can_cleanup_files
    false
  end

  #
  # @return [String] The session description
  #
  def desc
    'PostgreSQL'
  end

  protected

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    self.console.init_ui(self.user_input, self.user_output)
    self.console.set_log_source(self.log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    self.console.unset_log_source
    self.console.reset_ui
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Override the basic session interaction to use shell_read and
  # shell_write instead of operating on rstream directly.
  def _interact
    self.framework.events.on_session_interact(self)
    self.framework.history_manager.with_context(name: self.type.to_sym) { self._interact_stream }
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  def _interact_stream
    self.framework.events.on_session_interact(self)

    self.console.framework = self.framework
    # if framework.datastore['MeterpreterPrompt']
    #   console.update_prompt(framework.datastore['MeterpreterPrompt'])
    # end
    # Call the console interaction of the smb client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    self.console.interact { self.interacting != true }
    self.console.framework = nil

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise ::EOFError if (self.console.stopped? == true)
  end
end
