module OmniAuth
  module Kinde
    class TokenValidationError < StandardError
      attr_reader :error_reason
      def initialize(msg)
        @error_reason = msg
        super(msg)
      end
    end
  end
end