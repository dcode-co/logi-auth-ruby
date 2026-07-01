# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

require_relative "errors"
require_relative "id_token_verifier"

module LogiAuth
  # Server-side "Sign in with logi" for Ruby/Rails backends. Confidential-client
  # OAuth 2.0 code exchange + id_token (RS256) verification.
  #
  # Why this exists: a backend RP that skips the id_token +aud+ check can be
  # tricked into accepting a token minted for a DIFFERENT client (cross-client
  # account takeover). #exchange_code_and_verify ALWAYS verifies
  # signature + iss + aud + exp + nonce before returning +sub+.
  class Server
    Session = Struct.new(
      :sub, :email, :id_token, :access_token,
      :refresh_token, :expires_at, :scope, :claims,
      keyword_init: true
    )

    attr_reader :client_id, :redirect_uri, :issuer, :token_issuer, :default_scopes

    def initialize(client_id:, redirect_uri:, client_secret: nil,
                   issuer: "https://api.1pass.dev", token_issuer: "logi",
                   scopes: %w[openid profile:basic email], jwks_cache_ttl: 3600)
      raise ArgumentError, "client_id is required" if client_id.nil? || client_id.empty?
      raise ArgumentError, "redirect_uri is required" if redirect_uri.nil? || redirect_uri.empty?

      @client_id = client_id
      @redirect_uri = redirect_uri
      @client_secret = client_secret
      @issuer = issuer.sub(%r{/+\z}, "")
      @token_issuer = token_issuer
      @default_scopes = scopes
      @jwks_cache_ttl = jwks_cache_ttl
      @jwks_cache = nil
      @jwks_fetched_at = 0
    end

    # Build the /oauth/authorize URL to redirect the browser to.
    def authorization_url(state:, nonce:, scopes: nil, code_challenge: nil, prompt: nil)
      params = {
        "response_type" => "code",
        "client_id" => @client_id,
        "redirect_uri" => @redirect_uri,
        "scope" => (scopes || @default_scopes).join(" "),
        "state" => state,
        "nonce" => nonce
      }
      if code_challenge
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
      end
      params["prompt"] = prompt if prompt
      "#{@issuer}/oauth/authorize?#{URI.encode_www_form(params)}"
    end

    # Exchange the authorization code and verify the id_token. Returns a
    # verified Session (sub set only after signature + iss + aud + exp + nonce
    # all pass). Raises ServerError on any failure.
    def exchange_code_and_verify(code:, nonce:, code_verifier: nil)
      form = {
        "grant_type" => "authorization_code",
        "code" => code,
        "redirect_uri" => @redirect_uri,
        "client_id" => @client_id
      }
      form["client_secret"] = @client_secret if @client_secret
      form["code_verifier"] = code_verifier if code_verifier

      resp = http_post("#{@issuer}/oauth/token", form)
      unless success?(resp)
        raise ServerError.new("token_exchange_failed", "Token exchange failed (HTTP #{resp.code})",
                              detail: truncate(resp.body))
      end

      tokens = parse_token_body(resp.body)
      id_token = tokens["id_token"]
      unless id_token.is_a?(String) && !id_token.empty?
        raise ServerError.new("missing_id_token", "Token response had no id_token — was `openid` in the scopes?")
      end

      verified = verify_with_rotation_retry(id_token, nonce)
      email = verified.claims["email"]
      expires_in = tokens["expires_in"]

      Session.new(
        sub: verified.sub,
        email: email.is_a?(String) ? email : nil,
        id_token: id_token,
        access_token: tokens["access_token"],
        refresh_token: tokens["refresh_token"],
        expires_at: expires_in.is_a?(Numeric) ? Time.now.to_i + expires_in.to_i : nil,
        scope: tokens["scope"],
        claims: verified.claims
      )
    end

    private

    def verify_with_rotation_retry(id_token, nonce)
      expected = { issuer: @token_issuer, client_id: @client_id, nonce: nonce }
      jwks, from_cache = fetch_jwks(force: false)
      begin
        IdTokenVerifier.verify(id_token, jwks: jwks, expected: expected)
      rescue IdTokenError => e
        # Key rotation within the cache TTL — bust + refetch once.
        if e.code == "unknown_kid" && from_cache
          fresh, = fetch_jwks(force: true)
          begin
            IdTokenVerifier.verify(id_token, jwks: fresh, expected: expected)
          rescue IdTokenError => retry_err
            raise as_id_token_invalid(retry_err)
          end
        else
          raise as_id_token_invalid(e)
        end
      end
    end

    def as_id_token_invalid(err)
      ServerError.new("id_token_invalid", "id_token verification failed (#{err.code})", detail: err.code)
    end

    def fetch_jwks(force:)
      if !force && @jwks_cache && (Time.now.to_i - @jwks_fetched_at) < @jwks_cache_ttl
        return [@jwks_cache, true]
      end

      resp = http_get("#{@issuer}/.well-known/jwks.json")
      raise ServerError.new("jwks_fetch_failed", "JWKS fetch failed (HTTP #{resp.code})") unless success?(resp)

      jwks = begin
        parsed = JSON.parse(resp.body)
        raise "missing keys" unless parsed.is_a?(Hash) && parsed["keys"].is_a?(Array)

        parsed
      rescue JSON::ParserError, RuntimeError => e
        raise ServerError.new("jwks_fetch_failed", "JWKS response was malformed", detail: e.message)
      end

      @jwks_cache = jwks
      @jwks_fetched_at = Time.now.to_i
      [jwks, false]
    end

    def parse_token_body(body)
      tokens = JSON.parse(body)
      unless tokens.is_a?(Hash) && tokens["access_token"].is_a?(String)
        raise ServerError.new("token_exchange_failed", "Token response was missing access_token")
      end
      tokens
    rescue JSON::ParserError => e
      raise ServerError.new("token_exchange_failed", "Token response was not valid JSON", detail: e.message)
    end

    def http_post(url, form)
      uri = URI(url)
      req = Net::HTTP::Post.new(uri)
      req["Accept"] = "application/json"
      req.set_form_data(form)
      perform(uri, req)
    end

    def http_get(url)
      uri = URI(url)
      req = Net::HTTP::Get.new(uri)
      req["Accept"] = "application/json"
      perform(uri, req)
    end

    def perform(uri, req)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                                          open_timeout: 15, read_timeout: 15) do |http|
        http.request(req)
      end
    rescue StandardError => e
      raise ServerError.new("network_error", "Network error: #{e.message}", detail: e.message)
    end

    def success?(resp)
      (200..299).cover?(resp.code.to_i)
    end

    def truncate(str, limit = 2048)
      s = str.to_s
      s.length > limit ? "#{s[0, limit]}…[truncated]" : s
    end
  end
end
