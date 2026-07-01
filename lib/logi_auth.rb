# frozen_string_literal: true

# logi_auth — thin server-side "Sign in with logi" for Ruby / Rails backends.
# Confidential OAuth 2.0 code exchange + id_token (RS256) verification. Same
# safety contract as the iOS/Android/Web/Flutter/Node SDKs (shared golden
# vectors). Zero gem dependencies (stdlib OpenSSL + net/http + json).

require_relative "logi_auth/version"
require_relative "logi_auth/errors"
require_relative "logi_auth/id_token_verifier"
require_relative "logi_auth/server"

module LogiAuth
end
