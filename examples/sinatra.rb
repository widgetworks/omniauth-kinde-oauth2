$:.push File.dirname(__FILE__) + '/../lib'

require 'dotenv/load'
require 'sinatra'
require 'omniauth'
require 'omniauth-kinde-oauth2'

configure do
    set :sessions, true
end

use OmniAuth::Builder do
  provider :kinde_oauth2, ENV['KINDE_CLIENT_ID'], ENV['KINDE_CLIENT_SECRET'], ENV['KINDE_DOMAIN'],
    authorize_params: {
      scope: 'openid email profile offline'  #<- NEED these, otherwise we get ONLY a token
    }
end

# class MyKindeProvider
#   def self.client_id
#     ENV['KINDE_CLIENT_ID']
#   end
#
#   def self.client_secret
#     ENV['KINDE_CLIENT_SECRET']
#   end
# end
# use OmniAuth::Strategies::KindeOauth2, MyKindeProvider

get '/' do
  <<~HTML
    <form
      method="post"
      action="/auth/kinde_oauth2"
    >
        <input
          type="hidden"
          name="authenticity_token"
          value="#{request.env['rack.session']['csrf']}"
        />
        <button type='submit'>Login with Kinde</button>
    </form>
  HTML
end

get '/auth/kinde_oauth2/callback' do
  content_type 'text/plain'
  request.env['omniauth.auth'].inspect
end
