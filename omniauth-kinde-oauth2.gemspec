# -*- encoding: utf-8 -*-
require File.expand_path(File.join('..', 'lib', 'omniauth', 'kinde_oauth2', 'version'), __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Widget Works", "Mark Nadig"]
  gem.email         = ["support@widgetworks.com.au"]
  gem.description   = %q{A Kinde OAuth2 strategy for OmniAuth}
  gem.summary       = %q{A Kinde OAuth2 strategy for OmniAuth}
  gem.homepage      = "https://github.com/widgetworks/omniauth-kinde-oauth2"

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {spec}/*`.split("\n")
  gem.name          = "omniauth-kinde-oauth2"
  gem.require_paths = ["lib"]
  gem.version       = OmniAuth::KindeOauth2::VERSION
  gem.license       = "MIT"

  gem.add_runtime_dependency 'jwt', ['>= 1.0', '< 3.0']
  gem.add_runtime_dependency 'omniauth-oauth2', '~> 1.8'

  gem.add_development_dependency 'bundler'
end
