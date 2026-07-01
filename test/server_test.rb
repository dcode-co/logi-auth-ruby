# frozen_string_literal: true

require "minitest/autorun"
require "uri"
require_relative "../lib/logi_auth"

class ServerTest < Minitest::Test
  def build
    LogiAuth::Server.new(
      client_id: "logi_test_client_abc",
      client_secret: "secret_xyz",
      redirect_uri: "https://rp.example.com/auth/callback"
    )
  end

  def test_authorization_url_includes_nonce_state_and_pkce
    url = build.authorization_url(state: "st", nonce: "no", code_challenge: "cc")
    q = URI.decode_www_form(URI(url).query).to_h
    assert_equal "/oauth/authorize", URI(url).path
    assert_equal "logi_test_client_abc", q["client_id"]
    assert_equal "https://rp.example.com/auth/callback", q["redirect_uri"]
    assert_equal "st", q["state"]
    assert_equal "no", q["nonce"]
    assert_equal "cc", q["code_challenge"]
    assert_equal "S256", q["code_challenge_method"]
    assert_equal "openid profile:basic email", q["scope"]
  end

  def test_authorization_url_omits_pkce_when_absent
    url = build.authorization_url(state: "st", nonce: "no")
    q = URI.decode_www_form(URI(url).query).to_h
    refute q.key?("code_challenge")
  end

  def test_requires_client_id_and_redirect_uri
    assert_raises(ArgumentError) { LogiAuth::Server.new(client_id: "", redirect_uri: "x") }
    assert_raises(ArgumentError) { LogiAuth::Server.new(client_id: "x", redirect_uri: "") }
  end

  def test_exchange_rejects_nil_or_empty_nonce_before_any_network
    err = assert_raises(LogiAuth::ServerError) do
      build.exchange_code_and_verify(code: "c", nonce: nil)
    end
    assert_equal "invalid_nonce", err.code
    assert_raises(LogiAuth::ServerError) do
      build.exchange_code_and_verify(code: "c", nonce: "")
    end
  end
end
