require 'spec_helper'
require 'omniauth-kinde-oauth2'

module OmniAuth
  module Strategies
    module JWT; end
  end
end

describe OmniAuth::Strategies::KindeOauth2 do

  let(:client_id) { 'CLIENT_ID' }
  let(:client_secret) { 'CLIENT_SECRET' }
  let(:domain) { 'https://specs.kinde.com' }

  let(:request) { double('Request', :params => {}, :cookies => {}, :env => {}) }
  let(:app) {
    lambda do
      [200, {}, ["Hello."]]
    end
  }

  before do
    OmniAuth.config.test_mode = true
  end

  after do
    OmniAuth.config.test_mode = false
  end

  describe 'options' do
    let(:options) { @options || {} }
    subject do
      OmniAuth::Strategies::KindeOauth2.new(app, {
        client_id: client_id,
        client_secret: client_secret,
        domain: domain,
        authorize_params: {
          scope: 'openid email profile offline'
        }
      }.merge(options))
    end

    describe '#client' do
      it 'should have correct authorize path' do
        expect(subject.client.options[:authorize_url]).to eq('/oauth2/auth')
      end

      it 'should have the correct token path' do
        expect(subject.client.options[:token_url]).to eq('/oauth2/token')
      end

      it 'should have the correct userinfo path' do
        expect(subject.client.options[:userinfo_url]).to eq('/oauth2/user_profile')
      end

      it 'has correct authorize params' do
        allow(subject).to receive(:request) { request }
        subject.client
        expect(subject.authorize_params[:scope]).to eq('openid email profile offline')
        expect(subject.authorize_params[:state]).not_to be_nil
        expect(subject.authorize_params[:nonce]).not_to be_nil
      end
    end

  end

  # describe "raw_info" do
  #
  #   let(:basic_user_info) { {
  #     id => "kp_1234" ,
  #     first_name => "Firstname",
  #     last_name => "Lastname",
  #     preferred_email => "user@example.com",
  #     picture => nil,
  #     provided_id => nil,
  #     username => "MyUsername",
  #   } }
  #
  #   def stub_userinfo(body)
  #     stub_request(:get, 'https://specs.kinde.com/oauth2/user_profile')
  #       .to_return(
  #         headers: { 'Content-Type' => 'application/json' },
  #         body: MultiJson.encode(body)
  #       )
  #   end
  #
  #   subject do
  #     OmniAuth::Strategies::KindeOauth2.new(app, client_id, client_secret, domain)
  #   end
  #
  #   let(:token) do
  #     JWT.encode({"some" => "payload"}, "secret")
  #   end
  #
  #   let(:access_token) do
  #     double(:token => token)
  #   end
  #
  #   before do
  #     allow(subject).to receive(:access_token) { access_token }
  #     allow(subject).to receive(:request) { request }
  #   end
  #
  #   it "does not clash if JWT strategy is used" do
  #     expect do
  #       subject.info
  #     end.to_not raise_error
  #   end
  # end

end
