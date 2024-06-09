require 'bundler'

Bundler.require

require './sinatra'
# run(SinatraKindeApp, :Port => 4567)
Rackup::Handler.default.run(SinatraKindeApp, :Port => 4567)