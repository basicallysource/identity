# identity

Who somebody is, once, for every Basically surface: sign in with GitHub or
Discord, get one account, carry it everywhere. Other services never run their
own sign-in; they accept this service's tokens and ask it who a token belongs
to.

One Go binary, one SQLite file. No passwords, ever: GitHub and Discord prove
who people are, and the proof is used once and dropped. Tokens are opaque
random strings stored only as hashes, revocable at any moment.

## How a service uses it

Accept a bearer token, forward it:

    GET /v1/whoami
    Authorization: Bearer bsid_...

    {
      "account": "3f9c2a81d04b",
      "handle": "octocat",
      "created_at": "2026-08-27T00:00:00Z",
      "identities": [
        {"provider": "github", "id": "583231", "handle": "octocat", "proved_at": "..."}
      ],
      "token": {"id": "...", "name": "...", "audience": "https://app.example.com", "expires_at": "..."}
    }

`401` means the token is bad, expired, or revoked. That is the whole
integration: who this is, never application roles. Authorization stays each
service's own business. Applications must check `token.audience` against their
own origin before accepting a handoff token.

## How a person signs in

- **GitHub** is the device flow: `POST /signin/github/start` returns a code to
  type at github.com, `POST /signin/github/finish` polls until it turns into a
  token. Works from a browser, a terminal, or an app, with no redirect and no
  client secret.
- **Discord** is the standard redirect: `POST /signin/discord/start` returns
  the authorize URL, `GET /signin/discord/callback` receives the browser back.
- Either flow, started **with** a bearer token, links the newly proved
  identity to that account instead of signing in — that is how one account
  comes to hold both providers. An identity already proving a different
  account is refused, never moved.

The service also serves a small page at `/` that walks all of this for a
person: sign in, link the other provider, mint and revoke tokens.

Tokens: `GET /v1/tokens`, `POST /v1/tokens {"name": "..."}`,
`DELETE /v1/tokens/{id}`.

## How a service gets a browser signed in

Send the browser to `/authorize?redirect_uri=<your callback>&state=<yours>&code_challenge=<S256 challenge>`. Keep the random verifier server-side until the callback.
The page signs the person in (or already has them), then sends the browser
back to your callback with a one-time `code`. Exchange it server-side:

    POST /v1/exchange
    {"code": "...", "redirect_uri": "<the same callback>", "code_verifier": "..."}

which answers with a fresh audience-bound token for your server to hold. Use a
separate HttpOnly cookie for your application's session. Handoff tokens cannot
manage the identity account or obtain other application tokens. The identity
page keeps its own persistent HttpOnly session, so returning to it does not
require repeating provider sign-in while that session is live.

Callbacks must match `IDENTITY_REDIRECT_ALLOW`; prefer exact callback URLs. An
entry ending in `/` allows descendant paths on the same origin. Codes are
single-use, short-lived, bound to their callback and optional PKCE challenge,
and invalidated if their authorizing token is revoked. PKCE is recommended for
all browser consumers. There are no third-party client registrations or consent
screens; this service is for applications operated together.

## Running it

    go build ./cmd/identityd && ./identityd

Configuration is environment variables:

| variable | default | meaning |
|---|---|---|
| `IDENTITY_ADDR` | `:8870` | listen address |
| `IDENTITY_DB` | `identity.db` | SQLite path |
| `IDENTITY_BASE_URL` | `http://localhost:8870` | public base URL, used for the Discord redirect |
| `IDENTITY_GITHUB_CLIENT_ID` | — | a GitHub OAuth app with the device flow enabled |
| `IDENTITY_DISCORD_CLIENT_ID` | — | a Discord application |
| `IDENTITY_DISCORD_CLIENT_SECRET` | — | its secret |
| `IDENTITY_CLIENT_IP_HEADER` | — | the header a proxy in front sets to the real client address, e.g. `CF-Connecting-IP`; empty trusts none |
| `IDENTITY_REDIRECT_ALLOW` | — | comma-separated allowed callback URLs; a trailing slash allows descendants on the same origin; empty disables handoff |

A provider with no credentials set is simply not offered. The Discord app must
have `BASE_URL/signin/discord/callback` registered as a redirect, exactly.

See `agent-docs/architecture.md` for the decisions and their reasons.
