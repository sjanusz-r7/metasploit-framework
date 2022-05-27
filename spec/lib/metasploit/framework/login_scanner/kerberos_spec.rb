require 'spec_helper'
require 'metasploit/framework/login_scanner/kerberos'

RSpec.describe Metasploit::Framework::LoginScanner::Kerberos do
  let(:default_port) { 88 }
  let(:server_name) { 'msf6.local_server' }
  let(:realm) { 'msf6.local' }

  let(:successful_credential) do
    Metasploit::Framework::Credential.new(
      public: 'admin',
      private: 'admin',
      realm: realm
    )
  end

  let(:successful_tgt_request) do
    {
      server_name: server_name,
      client_name: successful_credential.public,
      password: successful_credential.private,
      realm: successful_credential.realm
    }
  end

  let(:successful_as_rep) do
    # instance_double(::Rex::Proto::Kerberos::Model::EncKdcResponse)
    instance_double(::Rex::Proto::Kerberos::Model::KdcResponse)
  end

  let(:successful_tgt_response) do
    ::Msf::Exploit::Remote::Kerberos::Model::Tgt.new(
      as_rep: successful_as_rep,
      preauth_required: true
    )
  end

  let(:locked_out_credential) do
    Metasploit::Framework::Credential.new(
      public: 'i_am_locked_out',
      private: 'a',
      realm: realm
    )
  end

  let(:locked_out_tgt_request) do
    {
      server_name: server_name,
      client_name: locked_out_credential.public,
      password: locked_out_credential.private,
      realm: locked_out_credential.realm
    }
  end

  let(:no_auth_credential) do
    Metasploit::Framework::Credential.new(
      public: 'no_auth',
      private: 'b',
      realm: realm
    )
  end

  let(:no_auth_tgt_request) do
    {
      server_name: server_name,
      client_name: no_auth_credential.public,
      password: no_auth_credential.private,
      realm: no_auth_credential.realm
    }
  end

  let(:no_auth_as_rep) do
    # instance_double(::Rex::Proto::Kerberos::Model::EncKdcResponse)
    instance_double(::Rex::Proto::Kerberos::Model::KdcResponse)
  end

  let(:no_auth_tgt_response) do
    Msf::Exploit::Remote::Kerberos::Model::Tgt.new(
      as_rep: no_auth_as_rep,
      preauth_required: false
    )
  end

  let(:incorrect_login_credential) do
    Metasploit::Framework::Credential.new(
      public: 'i_am_incorrect',
      private: nil,
      realm: realm
    )
  end

  let(:incorrect_login_tgt_request) do
    {
      server_name: server_name,
      client_name: incorrect_login_credential.public,
      password: incorrect_login_credential.private,
      realm: incorrect_login_credential.realm
    }
  end

  let(:incorrect_password_credential) do
    Metasploit::Framework::Credential.new(
      public: 'admin',
      private: 'i_am_incorrect',
      realm: realm
    )
  end

  let(:incorrect_password_tgt_request) do
    {
      server_name: server_name,
      client_name: incorrect_password_credential.public,
      password: incorrect_password_credential.private,
      realm: incorrect_password_credential.realm
    }
  end

  subject(:kerberos_scanner) { described_class.new({ server_name: server_name }) }

  it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: true, has_default_realm: true

  context '#attempt_login' do
    before(:each) do
      allow(subject).to receive(:send_request_tgt).with(successful_tgt_request).and_return(successful_tgt_response)
      allow(subject).to receive(:send_request_tgt).with(locked_out_tgt_request).and_raise(::Rex::Proto::Kerberos::Model::Error::KerberosError.new(error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED))
      allow(subject).to receive(:send_request_tgt).with(no_auth_tgt_request).and_return(no_auth_tgt_response)
      allow(subject).to receive(:send_request_tgt).with(incorrect_login_tgt_request).and_raise(::Rex::Proto::Kerberos::Model::Error::KerberosError.new(error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN))
      allow(subject).to receive(:send_request_tgt).with(incorrect_password_tgt_request).and_raise(::Rex::Proto::Kerberos::Model::Error::KerberosError.new(error_code: ::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED))
    end

    context 'when the login does not require authentication' do
      it 'returns the correct login status' do
        result = subject.attempt_login(no_auth_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(no_auth_tgt_response)
      end
    end

    context 'when the login is successful' do
      it 'returns the correct login status' do
        result = subject.attempt_login(successful_credential)

        # Note: Both correct login and no_preauth_required login attempts will be successful.
        expect(result.status).to eq(Metasploit::Model::Login::Status::SUCCESSFUL)
        expect(result.proof).to eq(successful_tgt_response)
      end
    end

    context 'when the login is locked out' do
      it 'returns the correct login status' do
        result = subject.attempt_login(locked_out_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::DISABLED)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_CLIENT_REVOKED)
      end
    end

    context 'when the login is incorrect' do
      it 'returns the correct login status' do
        result = subject.attempt_login(incorrect_login_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT_PUBLIC_PART)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_C_PRINCIPAL_UNKNOWN)
      end
    end

    context 'when the password is incorrect' do
      it 'returns the correct error code' do
        result = subject.attempt_login(incorrect_password_credential)

        expect(result.status).to eq(Metasploit::Model::Login::Status::INCORRECT)
        expect(result.proof.error_code).to eq(::Rex::Proto::Kerberos::Model::Error::ErrorCodes::KDC_ERR_PREAUTH_FAILED)
      end
    end
  end
end
