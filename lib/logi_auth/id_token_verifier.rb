# frozen_string_literal: true

require "openssl"
require "json"
require "base64"

require_relative "errors"

module LogiAuth
  # RS256 id_token verification — stdlib OpenSSL only (zero gem dependencies).
  # Mirrors the server (server/app/lib/oauth/jwt_verifier.rb) and the other
  # SDKs: kid -> JWKS -> RS256 signature -> iss / aud / exp / iat / nonce / sub.
  # Passes the shared 4-SDK golden vectors (../../test-vectors).
  #
  # Why not a JWT gem: iOS(Security.framework)/Web(WebCrypto)/Java(java.security)
  # each use their platform crypto primitive; Ruby's is stdlib OpenSSL. The JWS
  # parsing + claim checks are implemented here (mirroring verify.ts).
  #
  # Note: this is the public-client-neutral verification core. A confidential
  # Rails RP should call Server#exchange_code_and_verify, which uses this.
  module IdTokenVerifier
    Result = Struct.new(:sub, :claims, keyword_init: true)

    module_function

    # Verify +id_token+ and return a Result. Raises IdTokenError on any failure.
    # Claim order: signature -> iss -> aud -> exp -> iat -> nonce -> sub -> at_hash.
    #
    # jwks:         Hash with "keys" => [ {"kty","n","e","kid",...}, ... ]
    # expected:     { issuer:, client_id:, nonce: } (nonce optional)
    # now:          Unix seconds; defaults to Time.now. Injectable for tests.
    # access_token: OAuth access_token string. When both the payload carries an
    #   `at_hash` and this is provided, OIDC §3.1.3.6 at_hash binding is enforced
    #   (present-only): default nil skips the check, preserving backward compat.
    def verify(id_token, jwks:, expected:, now: nil, clock_skew_sec: 60, access_token: nil)
      now ||= Time.now.to_i

      parts = id_token.split(".")
      raise IdTokenError, "malformed" unless parts.length == 3 && parts.none? { |p| p.nil? || p.empty? }

      header = decode_json_segment(parts[0])
      payload = decode_json_segment(parts[1])
      raise IdTokenError, "malformed" if header.nil? || payload.nil?

      # Only RS256 is accepted — never verify a token whose header declares
      # another (or no) algorithm, even if the RSA signature happens to match.
      raise IdTokenError, "bad_signature" unless header["alg"] == "RS256"

      kid = header["kid"]
      raise IdTokenError, "missing_kid" unless kid.is_a?(String) && !kid.empty?

      # Tolerant JWKS key selection: pick the RS256 signing RSA key matching kid.
      # Guards against a future EC (or encryption) key sharing the kid space —
      # exact-match kty/use/alg filter keeps login working when JWKS gains keys.
      jwk = Array(jwks["keys"]).find do |k|
        k["kty"] == "RSA" &&
          (k["use"].nil? || k["use"] == "sig") &&
          (k["alg"].nil? || k["alg"] == "RS256") &&
          k["kid"] == kid
      end
      raise IdTokenError, "unknown_kid" if jwk.nil?

      signature = base64url_decode(parts[2])
      unless signature && verify_rs256("#{parts[0]}.#{parts[1]}", signature, jwk)
        raise IdTokenError, "bad_signature"
      end

      raise IdTokenError, "iss_mismatch" unless payload["iss"] == expected[:issuer]

      aud = payload["aud"]
      raise IdTokenError, "aud_mismatch" unless audience_matches?(aud, expected[:client_id])
      # OIDC §3.1.3.7: with multiple audiences an `azp` MUST be present; whenever
      # `azp` is present it MUST equal our client_id. Guards against accepting a
      # token issued to another authorized party that merely also lists us.
      azp = payload["azp"]
      if aud.is_a?(Array) && aud.length > 1
        raise IdTokenError, "aud_mismatch" unless azp == expected[:client_id]
      elsif !azp.nil?
        raise IdTokenError, "aud_mismatch" unless azp == expected[:client_id]
      end

      exp = numeric_claim(payload["exp"])
      raise IdTokenError, "expired" if exp.nil? || exp <= now - clock_skew_sec

      iat = numeric_claim(payload["iat"])
      # iat missing or in the future -> malformed (mirrors the other verifiers).
      raise IdTokenError, "malformed" if iat.nil? || iat > now + clock_skew_sec

      if expected[:nonce] && payload["nonce"] != expected[:nonce]
        raise IdTokenError, "nonce_mismatch"
      end

      sub = payload["sub"]
      raise IdTokenError, "missing_claim" unless sub.is_a?(String) && !sub.empty?

      # OIDC §3.1.3.6 at_hash — enforced last, present-only. If the payload
      # carries an at_hash and an access_token was supplied, they must bind:
      # base64url_nopad(SHA256(access_token bytes)[0...16]) == at_hash. Absent
      # at_hash or absent access_token skips the check (backward compatible).
      at_hash = payload["at_hash"]
      if access_token && at_hash.is_a?(String) && !at_hash.empty?
        raise IdTokenError, "at_hash_mismatch" unless at_hash == compute_at_hash(access_token)
      end

      Result.new(sub: sub, claims: payload)
    end

    # left-most 128 bits of SHA256(access_token), base64url without padding.
    def compute_at_hash(access_token)
      digest = OpenSSL::Digest::SHA256.digest(access_token.encode(Encoding::UTF_8))
      Base64.urlsafe_encode64(digest[0, 16], padding: false)
    end

    def verify_rs256(signing_input, signature, jwk)
      key = rsa_public_key(jwk)
      return false unless key

      key.verify(OpenSSL::Digest::SHA256.new, signature, signing_input)
    rescue OpenSSL::PKey::PKeyError, OpenSSL::OpenSSLError
      false
    end

    # Build an RSA public key from a JWK (n, e) via a SubjectPublicKeyInfo DER.
    def rsa_public_key(jwk)
      n_bytes = base64url_decode(jwk["n"])
      e_bytes = base64url_decode(jwk["e"])
      return nil unless n_bytes && e_bytes

      n = OpenSSL::BN.new(n_bytes, 2) # 2 = unsigned big-endian
      e = OpenSSL::BN.new(e_bytes, 2)
      pkcs1 = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::Integer(n), OpenSSL::ASN1::Integer(e)])
      algo = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("rsaEncryption"),
        OpenSSL::ASN1::Null.new(nil)
      ])
      spki = OpenSSL::ASN1::Sequence([algo, OpenSSL::ASN1::BitString.new(pkcs1.to_der)])
      OpenSSL::PKey::RSA.new(spki.to_der)
    rescue OpenSSL::OpenSSLError, ArgumentError
      nil
    end

    def decode_json_segment(segment)
      bytes = base64url_decode(segment)
      return nil unless bytes

      parsed = JSON.parse(bytes)
      parsed.is_a?(Hash) ? parsed : nil
    rescue JSON::ParserError
      nil
    end

    def audience_matches?(aud, client_id)
      case aud
      when String then aud == client_id
      when Array  then aud.include?(client_id)
      else false
      end
    end

    def numeric_claim(value)
      value.is_a?(Numeric) ? value.to_i : nil
    end

    def base64url_decode(str)
      return nil unless str.is_a?(String)

      pad = (4 - (str.length % 4)) % 4
      Base64.urlsafe_decode64(str + ("=" * pad))
    rescue ArgumentError
      nil
    end
  end
end
