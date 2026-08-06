# frozen_string_literal: true

module Msf::MCP
  module Middleware
    ##
    # Rack middleware that enforces Bearer token authentication on every request.
    #
    # The configured token is a static String. When the token is blank,
    # authentication is disabled (pass-through).
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
      # @param auth_token [String, nil] the bearer token to require
      def initialize(app, auth_token:)
        @app        = app
        @auth_token = auth_token.to_s
      end

      def call(env)
        # No token configured -> authentication disabled; pass through.
        return @app.call(env) if @auth_token.empty?

        expected = "Bearer #{@auth_token}"
        provided = env['HTTP_AUTHORIZATION'].to_s
        return UNAUTHORIZED unless Rack::Utils.secure_compare(expected, provided)

        @app.call(env)
      end
    end
  end
end
