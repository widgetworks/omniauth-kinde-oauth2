# frozen_string_literal: true

require 'securerandom'
require 'omniauth/strategies/oauth2'
require 'omniauth/kinde/jwt_validator'
require 'omniauth/kinde/errors'

module OmniAuth
  module Strategies
    class KindeOauth2 < OmniAuth::Strategies::OAuth2

      option :name, 'kinde_oauth2'

      args %i[
        client_id
        client_secret
        domain
      ]

      def client
        options.client_options.scope = 'openid email profile'
        options.client_options.site = domain_url
        options.client_options.authorize_url = "/oauth2/auth"
        options.client_options.token_url = "/oauth2/token"
        options.client_options.userinfo_url = '/oauth2/user_profile'
        super
      end

      # Use the "id" key of the userinfo returned
      # as the uid (globally unique string identifier).
      uid {
        raw_info['id']
      }

      # Build the API credentials hash with returned auth data.
      credentials do
        credentials = {
          'token' => access_token.token,
          'expires' => true
        }

        if access_token.params
          credentials.merge!(
            'id_token' => access_token.params['id_token'],
            'token_type' => access_token.params['token_type'],
            'refresh_token' => access_token.refresh_token
          )
        end

        # Retrieve and remove authorization params from the session
        # @type [Hash]
        session_authorize_params = (session['authorize_params'] || {})
        session.delete('authorize_params')

        auth_scope = session_authorize_params['scope']
        if auth_scope.respond_to?(:include?) && auth_scope.include?('openid')
          # Make sure the ID token can be verified and decoded.
          jwt_validator.verify(credentials['id_token'], session_authorize_params)
        end

        credentials
      end

      # CFH 2024-07-29 - exclude this extra information so we don't exceed
      # the 4k max cookie size.
      #
      # # Store all raw information for use in the session.
      # extra do
      #   {
      #     raw_info: raw_info
      #   }
      # end

      # Build a hash of information about the user
      # with keys taken from the Auth Hash Schema.
      info do
        {
          first_name: raw_info['first_name'],
          last_name: raw_info['last_name'],
          email: raw_info['preferred_email'],
        }
      end

      # Define the parameters used for the /auth endpoint
      def authorize_params
        params = super

        [
          'audience',
          'client_id',
          'code_challenge',
          'code_challenge_method',
          'connection_id',
          'is_create_org',
          'lang',
          'login_hint',
          'org_code',
          'org_name',
          'prompt',
          'redirect_uri',
          'response_type',
          'scope',
        ].each do |key|
          params[key] = request.params[key] if request.params.key?(key)
        end

        # Generate nonce
        params[:nonce] = SecureRandom.hex

        # Store authorize params in the session for token verification
        session['authorize_params'] = params.to_hash

        params
      end

      # Declarative override for the request phase of authentication
      def request_phase
        if no_client_id?
          # Do we have a client_id for this Application?
          fail!(:missing_client_id)
        elsif no_client_secret?
          # Do we have a client_secret for this Application?
          fail!(:missing_client_secret)
        else
          # All checks pass, run the Oauth2 request_phase method.
          super
        end
      end

      private

      def jwt_validator
        @jwt_validator ||= OmniAuth::Kinde::JWTValidator.new(options)
      end

      # userinfo returns an object like:
      #
      # {
      #   id="kp_012345abcdef012345abcdef012345ab"
      #   first_name="Firstname"
      #   last_name="Lastname"
      #   preferred_email="user@example.com"
      #   picture=nil
      #   provided_id=nil
      #   username="Username"
      # }
      def raw_info
        return @raw_info if @raw_info

        # Normally we would just decode the token and return that result,
        # but kinde doesn't include much of the needed information on that token:
        # @raw_info ||= ::JWT.decode(access_token.token, nil, false).first

        # Instead, we make another request and get the user information
        # from the `userinfo_url` endpoint (email, name, etc.)
        userinfo_url = options.client_options.userinfo_url
        @raw_info = access_token.get(userinfo_url).parsed

        return @raw_info
      end

      # Check if the options include a client_id
      def no_client_id?
        ['', nil].include?(options.client_id)
      end

      # Check if the options include a client_secret
      def no_client_secret?
        ['', nil].include?(options.client_secret)
      end

      # Check if the options include a domain
      def no_domain?
        ['', nil].include?(options.domain)
      end

      # Normalize a domain to a URL.
      def domain_url
        domain_url = URI(options.domain)
        domain_url = URI("https://#{domain_url}") if domain_url.scheme.nil?
        domain_url.to_s
      end

      def callback_url
        full_host + script_name + callback_path
      end

    end
  end
end
