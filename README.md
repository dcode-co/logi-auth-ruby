# logi_auth (Ruby)

Server-side **"Sign in with logi"** for Ruby / Rails backends — confidential
OAuth 2.0 Authorization Code exchange + **id_token (RS256) verification**. Zero
gem dependencies (stdlib `OpenSSL` + `net/http` + `json`).

This is the **confidential / backend** counterpart to the public-client SDKs
(browser, iOS, Android, Flutter). If your RP has a backend, verify on the
server with this gem — do **not** rely on a client-side check.

> **Why it matters:** a backend that skips the id_token `aud` check can be
> tricked into accepting a token minted for a *different* client (cross-client
> account takeover — the launchcrew/krx incident). `exchange_code_and_verify`
> always verifies signature + iss + aud + exp + nonce before returning `sub`.

## Supported versions

| Requirement | Version |
|-------------|---------|
| **Ruby** | **>= 3.0** (stdlib OpenSSL/JSON/net-http; no external gems) |
| **Rails** | any (**>= 6.1** tested pattern) — the gem is framework-agnostic; use it from any controller |
| Sinatra / Rack | any |

## Install

```ruby
# Gemfile
gem "logi_auth"
```

## Rails controller example

```ruby
# config/initializers/logi_auth.rb
LOGI = LogiAuth::Server.new(
  client_id: ENV.fetch("LOGI_CLIENT_ID"),
  client_secret: ENV.fetch("LOGI_CLIENT_SECRET"), # confidential client
  redirect_uri: "https://app.example.com/auth/logi/callback"
)

# app/controllers/logi_auth_controller.rb
class LogiAuthController < ApplicationController
  def start
    state = SecureRandom.hex(16)
    nonce = SecureRandom.hex(16)
    session[:logi_state] = state
    session[:logi_nonce] = nonce
    redirect_to LOGI.authorization_url(state: state, nonce: nonce), allow_other_host: true
  end

  def callback
    return head(:bad_request) unless params[:state] == session.delete(:logi_state)

    result = LOGI.exchange_code_and_verify(
      code: params[:code],
      nonce: session.delete(:logi_nonce)
    )
    # result.sub is the verified pairwise subject — key your User record on it.
    user = User.find_or_create_by!(logi_sub: result.sub) { |u| u.email = result.email }
    session[:user_id] = user.id
    redirect_to root_path
  rescue LogiAuth::ServerError => e
    redirect_to login_path, alert: "로그인 실패 (#{e.code})"
  end
end
```

## Public client (PKCE, no secret)

Omit `client_secret` and pass a `code_challenge` / `code_verifier`:

```ruby
logi = LogiAuth::Server.new(client_id:, redirect_uri:) # no secret
url = logi.authorization_url(state:, nonce:, code_challenge:)
result = logi.exchange_code_and_verify(code:, nonce:, code_verifier:)
```

## License

Apache-2.0
