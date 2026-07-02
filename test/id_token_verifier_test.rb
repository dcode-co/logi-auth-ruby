# frozen_string_literal: true

require "minitest/autorun"
require "json"
require_relative "../lib/logi_auth"

# Golden-vector parity test. test/fixtures/id-token-vectors.json is a copy of
# the 4-SDK shared set (test-vectors/id-token-vectors.json, SoT = generate.mjs).
# Ruby MUST produce identical verify/reject results to Web/iOS/Android/Flutter.
# JWKS is a fixed snapshot so this runs offline.
class IdTokenVerifierTest < Minitest::Test
  def setup
    @vectors = JSON.parse(File.read(File.join(__dir__, "fixtures", "id-token-vectors.json")))
    @expected = {
      issuer: @vectors["expected"]["issuer"],
      client_id: @vectors["expected"]["clientId"],
      nonce: @vectors["expected"]["nonce"]
    }
    @jwks = @vectors["jwks"]
    @now = @vectors["now"]
  end

  def test_golden_vectors
    @vectors["cases"].each do |c|
      name = c["name"]
      expect = c["expect"]
      # Cases carrying an accessToken exercise OIDC §3.1.3.6 at_hash present-only
      # binding; cases without it pass nil and skip at_hash (backward compatible).
      access_token = c["accessToken"]
      if expect["valid"]
        result = LogiAuth::IdTokenVerifier.verify(
          c["token"], jwks: @jwks, expected: @expected, now: @now, access_token: access_token
        )
        assert_equal expect["sub"], result.sub, "case '#{name}' sub mismatch" if expect["sub"]
      else
        err = assert_raises(LogiAuth::IdTokenError, "case '#{name}' expected to be rejected") do
          LogiAuth::IdTokenVerifier.verify(
            c["token"], jwks: @jwks, expected: @expected, now: @now, access_token: access_token
          )
        end
        assert_equal expect["error"], err.code, "case '#{name}' error code mismatch" if expect["error"]
      end
    end
  end

  def test_golden_vector_coverage
    assert_operator @vectors["cases"].length, :>=, 9
    assert(@vectors["cases"].any? { |c| c["name"] == "valid" })
  end

  # Explicit at_hash (OIDC §3.1.3.6) coverage: valid binding, mismatch rejection,
  # and present-at_hash-but-no-access_token skip (backward compatible).
  def test_at_hash_present_only_binding
    %w[at_hash_valid at_hash_mismatch at_hash_present_no_access_token].each do |n|
      assert(@vectors["cases"].any? { |c| c["name"] == n }, "missing at_hash case '#{n}'")
    end

    valid = @vectors["cases"].find { |c| c["name"] == "at_hash_valid" }
    result = LogiAuth::IdTokenVerifier.verify(
      valid["token"], jwks: @jwks, expected: @expected, now: @now, access_token: valid["accessToken"]
    )
    assert_equal "pairwise-sub-0001", result.sub

    mismatch = @vectors["cases"].find { |c| c["name"] == "at_hash_mismatch" }
    err = assert_raises(LogiAuth::IdTokenError) do
      LogiAuth::IdTokenVerifier.verify(
        mismatch["token"], jwks: @jwks, expected: @expected, now: @now, access_token: mismatch["accessToken"]
      )
    end
    assert_equal "at_hash_mismatch", err.code

    # at_hash present but no access_token supplied -> skipped, still valid.
    skip_case = @vectors["cases"].find { |c| c["name"] == "at_hash_present_no_access_token" }
    skipped = LogiAuth::IdTokenVerifier.verify(
      skip_case["token"], jwks: @jwks, expected: @expected, now: @now
    )
    assert_equal "pairwise-sub-0001", skipped.sub
  end
end
