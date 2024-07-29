require 'base64'
require 'uri'
require 'json'
require 'omniauth'
require 'omniauth/kinde/errors'

# This is taken from omniauth-auth0 jwt_validator.rb.
#
# We're not currently performing signature verification of the JWT
# (e.g. loading jwks certificates). But if we need to do that in future,
# then should refer back in the file history to reinstate it, or refer
# back to the original Auth0 implementation.
module OmniAuth
  module Kinde
    # JWT Validator class
    # rubocop:disable Metrics/
    class JWTValidator
      attr_accessor :issuer, :domain

      # Initializer
      # @param options object
      #   options.domain - Application domain.
      #   options.issuer - Application issuer (optional).
      #   options.client_id - Application Client ID.
      #   options.client_secret - Application Client Secret.

      def initialize(options, authorize_params = {})
        @domain = uri_string(options.domain)

        # Use custom issuer if provided, otherwise use domain
        @issuer = @domain
        @issuer = uri_string(options.issuer) if options.respond_to?(:issuer)

        @client_id = options.client_id
        @client_secret = options.client_secret
      end

      # Get the decoded head segment from a JWT.
      # @return hash - The parsed head of the JWT passed, empty hash if not.
      def token_head(jwt)
        jwt_parts = jwt.split('.')
        return {} if blank?(jwt_parts) || blank?(jwt_parts[0])

        json_parse(Base64.decode64(jwt_parts[0]))
      end

      # Decodes a JWT ~~and verifies it's signature. Only tokens signed with the RS256 or HS256 signatures are supported.~~
      # @param jwt string - JWT to verify.
      # @return hash - The decoded token, if there were no exceptions.
      # @see https://github.com/jwt/ruby-jwt
      def decode(jwt)
        head = token_head(jwt)
        key, alg = extract_key(head)

        # Call decode to verify the signature
        JWT.decode(jwt, nil, false, decode_opts(alg))
      end

      # Verify a JWT.
      # @param jwt string - JWT to verify.
      # @param authorize_params hash - Authorization params to verify on the JWT
      # @return hash - The verified token payload, if there were no exceptions.
      def verify(jwt, authorize_params = {})
        if !jwt
          raise OmniAuth::Kinde::TokenValidationError.new('ID token is required but missing')
        end

        parts = jwt.split('.')
        if parts.length != 3
          raise OmniAuth::Kinde::TokenValidationError.new('ID token could not be decoded')
        end

        id_token, header = decode(jwt)
        verify_claims(id_token, authorize_params)

        return id_token
      end

      private

      def extract_key(head)
        if head[:alg] == 'RS256'
          # key, alg = [rs256_decode_key(head[:kid]), head[:alg]]
          key, alg = ['⚠️head[:kid] is not being decoded at the moment⚠️', head[:alg]]
        elsif head[:alg] == 'HS256'
          key, alg = [@client_secret, head[:alg]]
        else
          raise OmniAuth::Auth0::TokenValidationError.new("Signature algorithm of #{head[:alg]} is not supported. Expected the ID token to be signed with RS256 or HS256")
        end
      end

      # Get the JWT decode options. We disable the claim checks since we perform our claim validation logic
      # Docs: https://github.com/jwt/ruby-jwt
      # @return hash
      def decode_opts(alg)
        {
          algorithm: alg,
          verify_expiration: false,
          verify_iat: false,
          verify_iss: false,
          verify_aud: false,
          verify_jti: false,
          verify_subj: false,
          verify_not_before: false
        }
      end

      # Rails Active Support blank method.
      # @param obj object - Object to check for blankness.
      # @return boolean
      def blank?(obj)
        obj.respond_to?(:empty?) ? obj.empty? : !obj
      end

      # Parse JSON with symbolized names.
      # @param json string - JSON to parse.
      # @return hash
      def json_parse(json)
        JSON.parse(json, symbolize_names: true)
      end

      # Parse a URI into the desired string format
      # @param uri - the URI to parse
      # @return string
      def uri_string(uri)
        temp_domain = URI(uri)
        temp_domain = URI("https://#{uri}") unless temp_domain.scheme
        temp_domain = temp_domain.to_s

        # NOTE CFH: it looks like Auth0 always includes a trailing slash in their domains
        # but kind *does not*. So we will change this to strip any trailing slashes instead.
        # temp_domain.end_with?('/') ? temp_domain : "#{temp_domain}/"
        temp_domain.chomp('/')
      end

      def verify_claims(id_token, authorize_params)
        leeway = authorize_params['leeway'] || 60
        max_age = authorize_params['max_age']
        nonce = authorize_params['nonce']
        organization = authorize_params['organization']

        verify_iss(id_token)
        verify_sub(id_token)
        verify_aud(id_token)
        verify_expiration(id_token, leeway)
        verify_iat(id_token)
        verify_nonce(id_token, nonce)
        verify_azp(id_token)
        verify_auth_time(id_token, leeway, max_age)
        verify_org(id_token, organization)
      end

      def verify_iss(id_token)
        issuer = id_token['iss']
        if !issuer
          raise OmniAuth::Kinde::TokenValidationError.new("Issuer (iss) claim must be a string present in the ID token")
        elsif @issuer != issuer
          raise OmniAuth::Kinde::TokenValidationError.new("Issuer (iss) claim mismatch in the ID token, expected (#{@issuer}), found (#{id_token['iss']})")
        end
      end

      def verify_sub(id_token)
        subject = id_token['sub']
        if !subject || !subject.is_a?(String) || subject.empty?
          raise OmniAuth::Kinde::TokenValidationError.new('Subject (sub) claim must be a string present in the ID token')
        end
      end

      def verify_aud(id_token)
        audience = id_token['aud']
        if !audience || !(audience.is_a?(String) || audience.is_a?(Array))
          raise OmniAuth::Kinde::TokenValidationError.new("Audience (aud) claim must be a string or array of strings present in the ID token")
        elsif audience.is_a?(Array) && !audience.include?(@client_id)
          raise OmniAuth::Kinde::TokenValidationError.new("Audience (aud) claim mismatch in the ID token; expected #{@client_id} but was not one of #{audience.join(', ')}")
        elsif audience.is_a?(String) && audience != @client_id
          raise OmniAuth::Kinde::TokenValidationError.new("Audience (aud) claim mismatch in the ID token; expected #{@client_id} but found #{audience}")
        end
      end

      def verify_expiration(id_token, leeway)
        expiration = id_token['exp']
        if !expiration || !expiration.is_a?(Integer)
          raise OmniAuth::Kinde::TokenValidationError.new("Expiration time (exp) claim must be a number present in the ID token")
        elsif expiration <= Time.now.to_i - leeway
          raise OmniAuth::Kinde::TokenValidationError.new("Expiration time (exp) claim error in the ID token; current time (#{Time.now}) is after expiration time (#{Time.at(expiration + leeway)})")
        end
      end

      def verify_iat(id_token)
        if !id_token['iat']
          raise OmniAuth::Kinde::TokenValidationError.new("Issued At (iat) claim must be a number present in the ID token")
        end
      end

      def verify_nonce(id_token, nonce)
        if nonce
          received_nonce = id_token['nonce']
          if !received_nonce
            raise OmniAuth::Kinde::TokenValidationError.new("Nonce (nonce) claim must be a string present in the ID token")
          elsif nonce != received_nonce
            raise OmniAuth::Kinde::TokenValidationError.new("Nonce (nonce) claim value mismatch in the ID token; expected (#{nonce}), found (#{received_nonce})")
          end
        end
      end

      def verify_azp(id_token)
        audience = id_token['aud']
        if audience.is_a?(Array) && audience.length > 1
          azp = id_token['azp']
          if !azp || !azp.is_a?(String)
            raise OmniAuth::Kinde::TokenValidationError.new("Authorized Party (azp) claim must be a string present in the ID token when Audience (aud) claim has multiple values")
          elsif azp != @client_id
            raise OmniAuth::Kinde::TokenValidationError.new("Authorized Party (azp) claim mismatch in the ID token; expected (#{@client_id}), found (#{azp})")
          end
        end
      end

      def verify_auth_time(id_token, leeway, max_age)
        if max_age
          auth_time = id_token['auth_time']
          if !auth_time || !auth_time.is_a?(Integer)
            raise OmniAuth::Kinde::TokenValidationError.new("Authentication Time (auth_time) claim must be a number present in the ID token when Max Age (max_age) is specified")
          elsif Time.now.to_i >  auth_time + max_age + leeway;
            raise OmniAuth::Kinde::TokenValidationError.new("Authentication Time (auth_time) claim in the ID token indicates that too much time has passed since the last end-user authentication. Current time (#{Time.now}) is after last auth time (#{Time.at(auth_time + max_age + leeway)})")
          end
        end
      end

      def verify_org(id_token, organization)
        return unless organization

        validate_as_id = organization.start_with? 'org_'

        if validate_as_id
          org_id = id_token['org_id']
          if !org_id || !org_id.is_a?(String)
            raise OmniAuth::Kinde::TokenValidationError,
                  'Organization Id (org_id) claim must be a string present in the ID token'
          elsif org_id != organization
            raise OmniAuth::Kinde::TokenValidationError,
                  "Organization Id (org_id) claim value mismatch in the ID token; expected '#{organization}', found '#{org_id}'"
          end
        else
          org_name = id_token['org_name']
          if !org_name || !org_name.is_a?(String)
            raise OmniAuth::Kinde::TokenValidationError,
                  'Organization Name (org_name) claim must be a string present in the ID token'
          elsif org_name != organization.downcase
            raise OmniAuth::Kinde::TokenValidationError,
                  "Organization Name (org_name) claim value mismatch in the ID token; expected '#{organization}', found '#{org_name}'"
          end
        end
      end
    end
  end
end
