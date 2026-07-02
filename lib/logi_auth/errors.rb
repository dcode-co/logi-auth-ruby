# frozen_string_literal: true

module LogiAuth
  # Base for all errors raised by this gem.
  class Error < StandardError; end

  # id_token verification failure. #code mirrors the Web verifier and the
  # golden-vector strings exactly (e.g. "bad_signature", "aud_mismatch").
  class IdTokenError < Error
    CODES = %w[
      malformed missing_kid unknown_kid bad_signature
      iss_mismatch aud_mismatch expired nonce_mismatch missing_claim
      at_hash_mismatch
    ].freeze

    attr_reader :code

    def initialize(code)
      @code = code
      super("id_token verification failed: #{code}")
    end
  end

  # Raised by Server for OAuth / transport failures.
  class ServerError < Error
    attr_reader :code, :detail

    def initialize(code, message, detail: nil)
      @code = code
      @detail = detail
      super(message)
    end
  end
end
