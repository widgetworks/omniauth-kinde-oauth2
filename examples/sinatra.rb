$:.push File.dirname(__FILE__) + '/../lib'

require 'omniauth-kinde-oauth2'
require 'sinatra'

class MyKindeProvider
  def self.client_id
    ENV['KINDE_CLIENT_ID']
  end

  def self.client_secret
    ENV['KINDE_CLIENT_SECRET']
  end
end

use Rack::Session::Cookie
use OmniAuth::Strategies::Kinde, MyKindeProvider

get '/' do
  "<a href='/auth/kinde_oauth2'>Log in with Kinde</a>"
end

get '/auth/kinde_oauth2/callback' do
  content_type 'text/plain'
  request.env['omniauth.auth'].inspect
end
