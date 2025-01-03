# OmniAuth Kinde Strategy

(NOTE: This is based on these gems: `omniauth-auth0` gem: https://github.com/auth0/omniauth-auth0.git and `omniauth-azure-oauth2` gem)

Authenticate with Kinde Oauth2 using OmniAuth.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'omniauth-kinde-oauth2'
```

## Configuration

First, you will need to add your site details to the Application in Kinde Admin:
  * [Get application keys](https://docs.kinde.com/get-started/connect/getting-app-keys/)
  * [Set callback and redirect URLs](https://docs.kinde.com/get-started/connect/callback-urls/)

Then add the `:kinde_oauth2` provider to your application configuration:

```ruby
use OmniAuth::Builder do
  provider :kinde_oauth2, ENV['KINDE_CLIENT_ID'], ENV['KINDE_CLIENT_SECRET'], ENV['KINDE_DOMAIN']
end
```

To configure params and things, just specify overrides as normal for OmniAuth provider:
(see options defined by the `omniauth-oauth2` gem: https://github.com/omniauth/omniauth-oauth2/blob/master/lib/omniauth/strategies/oauth2.rb)

```ruby
use OmniAuth::Builder do
  provider :kinde_oauth2, ENV['KINDE_CLIENT_ID'], ENV['KINDE_CLIENT_SECRET'], ENV['KINDE_DOMAIN'],
           authorize_params: {
             scope: 'openid email profile offline'
           }
end
```

Or the alternative format for use with [devise](https://github.com/heartcombo/devise):

```ruby
config.omniauth :kinde_oauth2, ENV['KINDE_CLIENT_ID'], ENV['KINDE_CLIENT_SECRET'], ENV['KINDE_DOMAIN']
```

## Auth Hash Schema

This is the structure of data returned from the Kinde `/userinfo` endpoint

```ruby
{
  id => "kp_012345abcdef012345abcdef012345ab",
  first_name => "Firstname",
  last_name => "Lastname",
  preferred_email => "user@example.com",
  picture => null,
  provided_id => null,
  username => "MyUsername",
}
```

## Example

To run the example Sinatra app:

1. Navigate to the examples directory: `cd examples`
2. Copy the `.env.example` file to `.env` and fill in the variables
3. Start the server: `bundle exec rackup`
4. In your browser, navigate to the server (defaults to: http://localhost:4567)


## Rake commands

Run tests `bundle exec rake`  
Push to rubygems `bundle exec rake release`.
