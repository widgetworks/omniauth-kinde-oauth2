require 'bundler'

Bundler.require

require './sinatra'
Rackup::Handler.default.run(SinatraKindeApp, :Port => 4567)
