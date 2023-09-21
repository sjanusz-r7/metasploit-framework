# -*- coding: binary -*-
#
# Author:: Michael Neumann
# Copyright:: (c) 2005 by Michael Neumann
# License:: Same as Ruby's or BSD
#

require 'postgres_msf'
require 'postgres/postgres-pr/message'
require 'postgres/postgres-pr/version'
require 'postgres/postgres-pr/scram_sha_256'
require 'uri'
require 'rex/socket'

# Namespace for Metasploit branch.
module Msf
module Db

module PostgresPR

PROTO_VERSION = 3 << 16   #196608

class AuthenticationMethodMismatch < StandardError
end

class Connection

  # Allow easy access to these instance variables
  attr_reader :conn, :params, :transaction_status

  # A block which is called with the NoticeResponse object as parameter.
  attr_accessor :notice_processor

  #
  # Returns one of the following statuses:
  #
  #   PQTRANS_IDLE    = 0 (connection idle)
  #   PQTRANS_INTRANS = 2 (idle, within transaction block)
  #   PQTRANS_INERROR = 3 (idle, within failed transaction)
  #   PQTRANS_UNKNOWN = 4 (cannot determine status)
  #
  # Not yet implemented is:
  #
  #   PQTRANS_ACTIVE  = 1 (command in progress)
  #
  def transaction_status
    case @transaction_status
    when ?I
      0
    when ?T
      2
    when ?E
      3
    else
      4
    end
  end

  def initialize(database, user, password = nil, uri = nil)
    uri ||= DEFAULT_URI

    @transaction_status = nil
    @params = {}
    establish_connection(uri)

    # Check if the password supplied is a Postgres-style md5 hash
    md5_hash_match = password.match(/^md5([a-f0-9]{32})$/)

    write_message(StartupMessage.new(PROTO_VERSION, 'user' => user, 'database' => database))

    loop do
      msg = Message.read(@conn)

      case msg
      when AuthentificationClearTextPassword
        raise ArgumentError, "no password specified" if password.nil?
        raise AuthenticationMethodMismatch, "Server expected clear text password auth" if md5_hash_match
        write_message(PasswordMessage.new(password))
      when AuthentificationCryptPassword
        raise ArgumentError, "no password specified" if password.nil?
        raise AuthenticationMethodMismatch, "Server expected crypt password auth" if md5_hash_match
        write_message(PasswordMessage.new(password.crypt(msg.salt)))
      when AuthentificationMD5Password
        raise ArgumentError, "no password specified" if password.nil?
        require 'digest/md5'

        if md5_hash_match
          m = md5_hash_match[1]
        else
          m = Digest::MD5.hexdigest(password + user)
        end
        m = Digest::MD5.hexdigest(m + msg.salt)
        m = 'md5' + m

        write_message(PasswordMessage.new(m))

      when AuthenticationSASL
        negotiate_sasl(msg, user, password)
      when UnknownAuthType
        raise "unknown auth type '#{msg.auth_type}' with buffer content:\n#{Rex::Text.to_hex_dump(msg.buffer.content)}"

      when AuthentificationKerberosV4, AuthentificationKerberosV5, AuthentificationSCMCredential
        raise "unsupported authentification"

      when AuthentificationOk
      when ErrorResponse
        handle_server_error_message(msg)
      when NoticeResponse
        @notice_processor.call(msg) if @notice_processor
      when ParameterStatus
        @params[msg.key] = msg.value
      when BackendKeyData
        # TODO
        #p msg
      when ReadyForQuery
        @transaction_status = msg.backend_transaction_status_indicator
        break
      else
        raise "unhandled message type"
      end
    end
  end

  def close
    raise "connection already closed" if @conn.nil?
    @conn.shutdown
    @conn = nil
  end

  class Result
    attr_accessor :rows, :fields, :cmd_tag
    def initialize(rows=[], fields=[])
      @rows, @fields = rows, fields
    end
  end

  # TODO: This could be moved out to a DB-agnostic module such as
  # ::Msf::Db::Interface::Query
  def query(sql)
    write_message(Query.new(sql))

    result = Result.new
    errors = []

    loop do
      msg = Message.read(@conn)
      case msg
      when DataRow
        result.rows << msg.columns
      when CommandComplete
        result.cmd_tag = msg.cmd_tag
      when ReadyForQuery
        @transaction_status = msg.backend_transaction_status_indicator
        break
      when RowDescription
        result.fields = msg.fields
      when CopyInResponse
      when CopyOutResponse
      when EmptyQueryResponse
      when ErrorResponse
        # TODO
        errors << msg
      when NoticeResponse
        @notice_processor.call(msg) if @notice_processor
      else
        # TODO
      end
    end

    raise errors.map{|e| e.field_values.join("\t") }.join("\n") unless errors.empty?

    result
  end

  def get_version_info
    return { error: :disconnected } unless @conn

    # Example output:
    # PostgreSQL 16.0 (Debian 16.0-1.pgdg120+1) on x86_64-pc-linux-gnu, compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit
    query_result = self.query('SELECT VERSION();')
    version_string = query_result.rows.first.first
    split_version_string = version_string.split

    version_info = {}
    version_info[:postgresql_version] = split_version_string[1]
    version_info[:platform_string] = split_version_string[5]
    version_info[:compiler_name] = split_version_string[8]
    version_info[:compiler_version] = split_version_string[11]

    version_info[:arch] = ::Rex::Arch::ARCH_X64 if split_version_string.last == '64-bit'
    version_info[:arch] = ::Rex::Arch::ARCH_X86 if split_version_string.last == '32-bit'
    version_info[:arch] = ::Rex::Arch::ARCH_ARMBE if split_version_string.last.downcase.include?('be')
    version_info[:arch] = ::Rex::Arch::ARCH_ARMLE if split_version_string.last.downcase.include?('le')
    version_info[:arch] = version_info[:arch] || 'unknown' # Default to unknown

    version_info[:platform] = ::Msf::Module::Platform::Windows if version_info[:platform_string].downcase.include?('win')
    version_info[:platform] = ::Msf::Module::Platform::Linux if version_info[:platform_string].downcase.include?('linux')
    version_info[:platform] = ::Msf::Module::Platform::OSX if version_info[:platform_string].downcase.include?('osx')
    version_info[:platform] = ::Msf::Module::Platform::Mac if version_info[:platform_string].downcase.include?('mac')
    version_info[:platform] = version_info[:platform] || 'unknown'

    @version_info = version_info
  end

  def version_info
    # This won't change on the same session.
    return @version_info if @version_info

    self.get_version_info
  end

  def get_databases
    return { error: :disconnected } unless @conn # Can't get the schema if we have disconnected.

    db_names_query = 'SELECT datname FROM pg_database;'
    self.query(db_names_query).rows.flatten
  end

  def get_tables(database: '')
    return { error: :disconnected } unless @conn # Can't get the schema if we have disconnected.

    require 'pry-byebug'; binding.pry

    #table_names_query = "SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname == #{database};"
    table_names_query = "SELECT tablename FROM pg_catalog.pg_tables WHERE tableowner == #{database};"
    self.query(table_names_query).rows.flatten
  end

  def get_columns(table: '')
    return { error: :disconnected } unless @conn # Can't get the schema if we have disconnected.

    column_names_query = "SELECT * FROM #{table};"
    self.query(column_names_query).rows.flatten
  end

  def get_schema(ignored_databases: [])
    return { error: :disconnected } unless @conn # Can't get the schema if we have disconnected.

    pg_schema = {}
    database_names = self.get_databases
    pg_schema[:all_databases] = database_names

    return pg_schema if database_names.empty?

    excluded_databases = (database_names & ignored_databases)
    pg_schema[:ignored_databases] = excluded_databases

    pg_schema[:evaluated_databases] = []

    extractable_database_names = database_names - ignored_databases
    extractable_database_names.each do |database_name|
      tmp_db = {}
      tmp_db[:DBName] = database_name
      tmp_db[:Tables] = []

      # We are already logged in but double-check this
      #postgres_login({ database: database_name })

      # TODO: Does this get the tables for all databases?
      #
      #table_names_query = "SELECT c.relname, n.nspname FROM pg_catalog.pg_class c LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','pg_toast') AND pg_catalog.pg_table_is_visible(c.oid);"
      #tmp_tblnames = self.query(table_names_query).rows.flatten
      #tmp_tblnames = self.get_tables(database: database_name)
      #if tmp_tblnames && !tmp_tblnames.empty?
      #  tmp_tblnames.each do |tbl_row|
      #    tmp_tbl = {}
      #    tmp_tbl[:TableName] = tbl_row[0]
      #    tmp_tbl[:Columns] = []
      #    # TODO: Add self.columns(database: db)
      #    #column_names_query = "SELECT  A.attname, T.typname, A.attlen FROM pg_class C, pg_namespace N, pg_attribute A, pg_type T WHERE  (N.oid=C.relnamespace) AND (A.attrelid=C.oid) AND (A.atttypid=T.oid) AND (A.attnum>0) AND (NOT A.attisdropped) AND (N.nspname ILIKE 'public') AND (c.relname='#{tbl_row[0]}');"
      #    tmp_column_names = self.get_columns(table: tbl_row[0])
      #    if tmp_column_names && !tmp_column_names.empty?
      #      tmp_column_names.each do |column_row|
      #        tmp_column = {}
      #        tmp_column[:ColumnName] = column_row[0]
      #        tmp_column[:ColumnType] = column_row[1]
      #        tmp_column[:ColumnLength] = column_row[2]
      #        tmp_tbl[:Columns] << tmp_column
      #      end
      #    end
      #    tmp_db[:Tables] << tmp_tbl
      #  end
      #end
      pg_schema[:evaluated_databases] << tmp_db
    end

    pg_schema
  end

  # @param [AuthenticationSASL] msg
  # @param [String] user
  # @param [String,nil] password
  def negotiate_sasl(msg, user, password = nil)
    if msg.mechanisms.include?('SCRAM-SHA-256')
      scram_sha_256 = ScramSha256.new
      # Start negotiating scram, additionally wrapping in SASL and unwrapping the SASL responses
      scram_sha_256.negotiate(user, password) do |state, value|
        if state == :client_first
          sasl_initial_response_message = SaslInitialResponseMessage.new(
            mechanism: 'SCRAM-SHA-256',
            value: value
          )

          write_message(sasl_initial_response_message)

          sasl_continue = Message.read(@conn)
          raise handle_server_error_message(sasl_continue) if sasl_continue.is_a?(ErrorResponse)
          raise AuthenticationMethodMismatch, "Did not receive AuthenticationSASLContinue - instead got #{sasl_continue}" unless sasl_continue.is_a?(AuthenticationSASLContinue)

          server_first_string = sasl_continue.value
          server_first_string
        elsif state == :client_final
          sasl_initial_response_message = SASLResponseMessage.new(
            value: value
          )

          write_message(sasl_initial_response_message)

          server_final = Message.read(@conn)
          raise handle_server_error_message(server_final) if server_final.is_a?(ErrorResponse)
          raise AuthenticationMethodMismatch, "Did not receive AuthenticationSASLFinal - instead got #{server_final}" unless server_final.is_a?(AuthenticationSASLFinal)

          server_final_string = server_final.value
          server_final_string
        else
          raise AuthenticationMethodMismatch, "Unexpected negotiation state #{state}"
        end
      end
    else
      raise AuthenticationMethodMismatch, "unsupported SASL mechanisms #{msg.mechanisms.inspect}"
    end
  end

  DEFAULT_PORT = 5432
  DEFAULT_HOST = 'localhost'
  DEFAULT_PATH = '/tmp'
  DEFAULT_URI =
    if RUBY_PLATFORM.include?('win')
      'tcp://' + DEFAULT_HOST + ':' + DEFAULT_PORT.to_s
    else
      'unix:' + File.join(DEFAULT_PATH, '.s.PGSQL.' + DEFAULT_PORT.to_s)
    end

  private

  # @param [ErrorResponse] server_error_message
  # @raise [RuntimeError]
  def handle_server_error_message(server_error_message)
    raise server_error_message.field_values.join("\t")
  end

  # tcp://localhost:5432
  # unix:/tmp/.s.PGSQL.5432
  def establish_connection(uri)
    u = URI.parse(uri)
    case u.scheme
    when 'tcp'
      @conn = Rex::Socket.create(
      'PeerHost' => (u.host || DEFAULT_HOST).gsub(/[\[\]]/, ''),  # Strip any brackets off (IPv6)
      'PeerPort' => (u.port || DEFAULT_PORT),
      'proto' => 'tcp'
    )
    when 'unix'
      @conn = UNIXSocket.new(u.path)
    else
      raise 'unrecognized uri scheme format (must be tcp or unix)'
    end
  end

  # @param [Message] message
  # @return [Numeric] The byte count successfully written to the currently open connection
  def write_message(message)
    @conn << message.dump
  end
end

end # module PostgresPR

end
end
