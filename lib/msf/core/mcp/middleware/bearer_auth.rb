# frozen_string_literal: true

module Msf::MCP
  module Middleware
    ##
    # Rack middleware that enforces Bearer token authentication on every request.
    #
    # The configured token may be a static String or a callable (resolved per
    # request). A callable lets embedders change the token at runtime without
    # rebuilding the Rack stack (e.g. Metasploit Pro reading it from settings).
    # When the resolved token is blank, authentication is disabled (pass-through).
    #
    # Clients must send:
    #   Authorization: Bearer <token>
    #
    # Returns 401 with a WWW-Authenticate challenge on any mismatch.
    # Comparison is constant-time via +Rack::Utils.secure_compare+ to prevent
    # timing-based token enumeration.
    #
    class BearerAuth
      UNAUTHORIZED = [
        401,
        {
          'Content-Type'    => 'application/json',
          'WWW-Authenticate' => 'Bearer realm="msfmcp"'
        },
        ['{"error":"Unauthorized"}']
      ].freeze

      # @param app [#call] the downstream Rack app
      # @param auth_token [String, #call, nil] a static token or a callable
      #   returning the current token
      def initialize(app, auth_token:)
        @app        = app
        @auth_token = auth_token
      end

      def call(env)
        token = current_token
        # No token configured -> authentication disabled; pass through.
        return @app.call(env) if token.empty?

        expected = "Bearer #{token}"
        provided = env['HTTP_AUTHORIZATION'].to_s
        return UNAUTHORIZED unless Rack::Utils.secure_compare(expected, provided)

        @app.call(env)
      end

      private

      # Resolve the configured token for the current request. Supports a static
      # String or a callable so the token can change without rebuilding the stack.
      #
      # @return [String]
      def current_token
        value = @auth_token.respond_to?(:call) ? @auth_token.call : @auth_token
        value.to_s
      end
    end
  end
end
