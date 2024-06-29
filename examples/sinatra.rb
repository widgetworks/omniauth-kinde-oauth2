$:.push File.dirname(__FILE__) + '/../lib'

require 'dotenv/load'
require 'sinatra'
require 'omniauth'
require 'omniauth-kinde-oauth2'

class SinatraKindeApp < Sinatra::Base

  configure do
    set :sessions, true
    set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(64) }
  end

  use OmniAuth::Builder do
    provider :kinde_oauth2, ENV['KINDE_CLIENT_ID'], ENV['KINDE_CLIENT_SECRET'], ENV['KINDE_DOMAIN'],
      authorize_params: {
        scope: 'openid email profile offline'  #<- NEED these, otherwise we get ONLY a token
      }
  end

  get '/' do
    if session[:auth_info]
      redirect to('/logged_in')
    else
      erb :index, locals: {
        request_csrf: request.env['rack.session']['csrf']
      }
    end
  end

  get '/auth/kinde_oauth2/callback' do
    # CFH - save token in "session"
    # redirect to the "logged_in" page
    # and show the token there
    content_type 'text/plain'
    auth_info = request.env['omniauth.auth']
    session[:auth_info] = auth_info

    # auth_info.inspect

    redirect to('/logged_in')
  end

  get '/logged_in' do
    if session[:auth_info]
      erb :logged_in, :locals => {
        session: session,
      }
    else
      # clear session?
      redirect to('/')
    end
  end

  post '/log_out' do
    if session[:auth_info]
      # do log out
      kinde_domain = ENV['KINDE_DOMAIN']
      local_domain = "http://localhost:4567/logged_out"
      clear_session_auth()
      redirect "https://#{kinde_domain}/logout?redirect=#{local_domain}"
    else
      redirect to('/')
    end
  end

  get '/logged_out' do
    erb :index, locals: {
      request_csrf: request.env['rack.session']['csrf']
    }
  end

  private

  def clear_session_auth
    session[:auth_info] = nil
  end

end
