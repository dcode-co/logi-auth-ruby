# frozen_string_literal: true

require_relative "lib/logi_auth/version"

Gem::Specification.new do |spec|
  spec.name = "logi_auth"
  spec.version = LogiAuth::VERSION
  spec.authors = ["Dcode"]
  spec.summary = "Server-side \"Sign in with logi\" for Ruby/Rails — confidential OAuth 2.0 + id_token (RS256) verification."
  spec.description = "Thin backend connector for logi (1pass) as an identity provider. Confidential-client " \
                     "code exchange with mandatory id_token verification (signature + iss + aud + exp + nonce). " \
                     "Zero gem dependencies (stdlib OpenSSL + net/http)."
  spec.homepage = "https://github.com/dcode-co/logi-auth-ruby"
  spec.license = "Apache-2.0"

  spec.required_ruby_version = ">= 3.0"

  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true"
  }

  spec.files = Dir["lib/**/*.rb"] + %w[LICENSE NOTICE README.md]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
end
