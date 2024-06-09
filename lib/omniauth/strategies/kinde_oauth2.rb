# DEV ONLY
require 'json'
# DEV ONLY

require 'securerandom'
require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class KindeOauth2 < OmniAuth::Strategies::OAuth2

      option :name, 'kinde_oauth2'

      option :pkce, false

      args %i[
        client_id
        client_secret
        domain
      ]

      def client
        options.client_options.scope = 'openid email profile'
        options.client_options.pkce_enabled = false
        options.client_options.site = domain_url
        options.client_options.authorize_url = "/oauth2/auth"
        options.client_options.token_url = "/oauth2/token"
        options.client_options.userinfo_url = '/oauth2/user_profile'

        # options.client_options.debugging = false
        options.client_options.debugging = true
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'],
        }
      end

      # # Define the parameters used for the /authorize endpoint
      # def authorize_params
      #   params = super
      #   [
      #     'audience',
      #     'client_id',
      #     'code_challenge',
      #     'code_challenge_method',
      #     'connection_id',
      #     'is_create_org',
      #     'lang',
      #     'login_hint',
      #     'org_code',
      #     'org_name',
      #     'prompt',
      #     'redirect_uri',
      #     'response_type',
      #     'scope',
      #     'state',
      #   ].each do |key|
      #     params[key] = request.params[key] if request.params.key?(key)
      #   end
      #
      #   # # Generate nonce
      #   # params[:nonce] = SecureRandom.hex
      #   # # Generate leeway if none exists
      #   # params[:leeway] = 60 unless params[:leeway]
      #   #
      #   # # Store authorize params in the session for token verification
      #   # session['authorize_params'] = params.to_hash
      #
      #   params
      # end

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
          'state',
        ].each do |key|
          params[key] = request.params[key] if request.params.key?(key)
        end

        # Generate nonce
        params[:nonce] = SecureRandom.hex

        # # Store authorize params in the session for token verification
        # session['authorize_params'] = params.to_hash

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

      def raw_info
        return @raw_info if @raw_info

        puts "access_token\n\n"
        puts access_token.to_json
        puts "end access_token\n\n"

        # @raw_info ||= ::JWT.decode(access_token.token, nil, false).first

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