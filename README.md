# identity

Who somebody is, once, for every service operated together: sign in with
GitHub or Discord, get one account, carry it everywhere. Other services never
run their own sign-in; they accept this service's tokens and ask it who a
token belongs to.

One Go binary, one SQLite file. No passwords, ever: GitHub and Discord prove
who people are, and the proof is used once and dropped. Tokens are opaque
random strings stored only as hashes, revocable at any moment.

## The contract

[`api/openapi.yaml`](api/openapi.yaml) describes every route. It is held to
the implementation by tests: every route is described, every described path
is served, and every response the test suite provokes is validated against
the schemas. `api/gen.go` is a Go client generated from it (`go generate
./api`, committed, CI diffs). A TypeScript client would come from the same
file with `openapi-typescript`.

## How a Go service uses it

Import the client package. It is the security rules as code, so the next
service cannot forget one:

```go
auth, err := client.New(client.Config{
    IdentityURL: "https://identity.example",
    BaseURL:     "https://app.example",   // this service's public origin
    Key:         key,                     // 32 random bytes, from the environment
})
auth.Routes(mux)                          // /auth/signin, /auth/callback, /auth/signout, /auth/me
mux.Handle("/admin/", auth.RequireGroup("basically-core", adminHandler))
mux.Handle("/", auth.Require(pageHandler))
```

Behind `Require`, `client.WhoFrom(r.Context())` is the person: account id,
handle, provider identities, and `who.In("group")`. `client.TokenFrom(r.Context())`
is their token, for calls the service makes to identity on their behalf, such
as their profile photo; it goes nowhere else. Code that answers who is signed
in itself, outside a gate, uses `auth.Check(r)`, whose error tells
`client.ErrSignedOut` from `client.ErrUnavailable` (identity could not be
asked, so say neither yes nor no), and a script's bearer token is checked with
`auth.WhoToken(ctx, token)`. The browser is sent to
`/authorize` here with a PKCE challenge, comes back with a one-time code, the
code is exchanged server-side for an application token, and that token lives
sealed inside an HttpOnly cookie. Every `whoami` answer is checked against
the service's own origin (`token.audience`) and re-asked every five minutes,
so a revocation or a group change lands within that window.

The service's callback URL (`BaseURL` + `/auth/callback`) must be in
`IDENTITY_REDIRECT_ALLOW`.

One sign-in carries across every service. A browser already signed in here
is sent straight back with a code, and a page that shows its own sign-in
button can ask first with `prompt=none`, which comes back with
`error=login_required` instead of showing anything. Signing out of any
service signs that browser out here and out of every service its sign-in
reached; the client package does both.

## Groups

The one thing this service says about authorization: which accounts are in
which named group. `whoami` answers `"groups": ["basically-core", ...]`,
always present, sorted. **What a group means is each service's own
decision**: this service holds membership, a service holds the rule
("members of basically-core may open the admin page"). Onboarding and
offboarding are one act, here.

Groups are flat. If nesting ever exists, `whoami` will flatten it, so no
consumer has to know.

`identity-admin` is reserved: its members manage groups on this service's
page, it cannot be deleted, and its last member cannot be removed. The first
administrator is made at the terminal, since nobody can be one through the
API before somebody is:

    identityd grant identity-admin <handle-or-account-id>

Also `identityd accounts`, `identityd groups`, `identityd revoke`. Every
change, from the page or the terminal, is in the audit log.

## Any service, by hand

Accept a bearer token, forward it:

    GET /v1/whoami
    Authorization: Bearer bsid_...

    {
      "account": "3f9c2a81d04b",
      "handle": "octocat",
      "created_at": "2026-08-27T00:00:00Z",
      "identities": [
        {"provider": "github", "id": "583231", "handle": "octocat", "proved_at": "...", "avatar": {...}}
      ],
      "groups": ["basically-core"],
      "avatar": {"id": "...", "width": 460, "height": 460, "source": "github"},
      "token": {"id": "...", "name": "...", "audience": "https://app.example", "expires_at": "..."}
    }

`401` means the token is bad, expired, or revoked. A browser-facing service
must check `token.audience` against its own origin before trusting the
answer; the client package does this for you.

To sign a person out, send their token to `POST /v1/signout`. It revokes the
browser sign-in the token was handed off from, and every token minted from
that sign-in, this one included.

## How a person signs in

The page at `/` does it: sign in with GitHub (device flow, works from a
terminal too) or Discord (redirect), link the other provider, choose a
profile photo, mint and revoke tokens, and, for `identity-admin`, manage
groups. It is server-rendered HTML with htmx; there is no token in the
browser. Signing out here, or revoking a browser's session from the token
list, signs that browser out of every service it reached from it.

Either sign-in flow started **with** a bearer token links the newly proved
identity to that account instead. An identity already proving a different
account is refused, never moved.

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
| `IDENTITY_ASSET_URL` | — | asset-service API origin; enables profile photos when configured |
| `IDENTITY_ASSET_TOKEN` | — | server credential with read/write access to the photo namespace |
| `IDENTITY_ASSET_NAMESPACE` | `profile-avatars` | private photo namespace |
| `IDENTITY_STORAGE_ORIGIN` | — | allowed origin of private signed object URLs |

A provider with no credentials set is simply not offered. The Discord app must
have `BASE_URL/signin/discord/callback` registered as a redirect, exactly.

Developing the page: `cd internal/api/web && npm ci && npm run build`
rebuilds `style.css` from the templates; the output is committed.

See `agent-docs/architecture.md` for the decisions and their reasons.
