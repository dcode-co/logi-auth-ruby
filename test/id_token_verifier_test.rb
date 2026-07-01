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
      if expect["valid"]
        result = LogiAuth::IdTokenVerifier.verify(c["token"], jwks: @jwks, expected: @expected, now: @now)
        assert_equal expect["sub"], result.sub, "case '#{name}' sub mismatch" if expect["sub"]
      else
        err = assert_raises(LogiAuth::IdTokenError, "case '#{name}' expected to be rejected") do
          LogiAuth::IdTokenVerifier.verify(c["token"], jwks: @jwks, expected: @expected, now: @now)
        end
        assert_equal expect["error"], err.code, "case '#{name}' error code mismatch" if expect["error"]
      end
    end
  end

  def test_golden_vector_coverage
    assert_operator @vectors["cases"].length, :>=, 9
    assert(@vectors["cases"].any? { |c| c["name"] == "valid" })
  end
end
