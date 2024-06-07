require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class KindeOauth2 < OmniAuth::Strategies::OAuth2
      BASE_KINDE_URL = 'https://widgetworks.kinde.com'

      option :name, 'kinde_oauth2'

      option :pkce, false

      option :tenant_provider, nil

      # tenant_provider must return client_id, client_secret and optionally base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.client_id
        options.client_secret = provider.client_secret
        options.base_kinde_url =
          provider.respond_to?(:base_kinde_url) ? provider.base_kinde_url : BASE_KINDE_URL

        options.authorize_params = provider.authorize_params if provider.respond_to?(:authorize_params)
        options.authorize_params.prompt = request.params['prompt'] if defined? request && request.params['prompt']
        options.client_options.authorize_url = "#{options.base_kinde_url}/oauth2/auth"
        options.client_options.token_url = "#{options.base_kinde_url}/oauth2/token"

        # options.client_options.debugging = false
        options.client_options.debugging = true
        super
      end

      uid {
        # raw_info['sub']
        raw_info['id']
      }

      info do
        {
          first_name: raw_info['first_name'],
          last_name: raw_info['last_name'],
          email: raw_info['email'],
        }
      end

      def callback_url
        full_host + callback_path
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token.token, nil, false).first
      end

    end
  end
end
