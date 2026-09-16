# Architecture

Identity proves an account and says which groups it is in; each consuming
application decides what that means for what the account may read or change.
An account has a random internal ID. Provider identities are attached by
immutable GitHub or Discord IDs, never by handle or email.

## The contract

`api/openapi.yaml` is the API. Three things hold it to the code, all in
`internal/api/contract_test.go`: the route table (`server.go`) and the spec are
the same set in both directions; every response the test suite provokes is
validated against the spec's schemas, because `newTestServer` wraps the handler
in a validator; and `api/gen.go`, the generated Go client, is regenerated and
diffed by CI. Routes come in three kinds: API routes must be in the spec, page
routes (the HTML and its htmx fragments) and static files must not be.

Request validation is deliberately not part of the test: tests send malformed
requests to see them refused, and the refusal is what the spec has to describe.

## Groups

Groups are the one authorization fact this service holds: a named, flat set of
accounts. `whoami` answers the sorted list of names an account is in, always
present. Nothing here knows what a name means; a consumer configures "admin =
basically-core" and asks `who.In`. That split is deliberate: membership changes
in one place and takes effect everywhere, while the meaning of a group lives
next to the code that enforces it.

Flat, not nested. "Who is in X" and "what is A in" are each one indexed read
with no graph to walk, and the wire shape (a flat list of effective names)
would not change if nesting were ever added and flattened server-side.

`identity-admin` is reserved: its members administer groups, it cannot be
deleted, and its last member cannot be removed, so the service cannot lock
itself out. Administration needs an account token; the secure middleware
refuses application tokens anything past whoami and avatar, so a consumer's
handoff credential cannot manage groups even for an administrator. The first
administrator is made with the `identityd grant` command against the database,
since no API caller can be one before somebody is. Every change is audited in
the same transaction, with the actor's account id or `cli`.

## The client package

`client` is the consuming side, so that the rules live in one place: PKCE on
the authorize request, the exchange server-side, the audience check on every
whoami, the token sealed with AES-GCM inside an HttpOnly cookie, a whoami cache
with a short recheck so revocation is seen within minutes, and `Require` /
`RequireGroup` gates. It has no session table; the sealed cookie is the
session, and rotating the key signs everyone out. Signing out goes through
identity's `/v1/signout` first, and a silent (`prompt=none`) sign-in is there
for pages that show their own button. It is tested end to end against the
real server in `internal/api`.

## Sign-in and linking

GitHub uses device flow. Discord uses its authorization-code redirect flow.
Provider access tokens are used once to fetch identity, then discarded.
Starting either flow while authenticated links that provider to the current
account. An identity already attached to another account is refused. Signing
in separately with two providers creates two accounts; there is no email-based
matching or account merge operation.

Browser sign-in uses a persistent, host-only HttpOnly cookie. HTTPS deployments
use the `__Host-identity` cookie prefix and Secure flag. The cookies that carry
a sign-in in progress, the pending authorize request and Discord's state, are
`__Host-` cookies on HTTPS too, so a sibling subdomain cannot plant one to steer
a sign-in; plain names are used only on local HTTP. The cookie holds an opaque
account token whose secret is stored only as a hash in SQLite. Sign-out revokes
it, and every application token minted from it. The browser script does not
receive that token. GitHub CLI sign-in still returns a token; the browser
requests cookie mode with `X-Identity-Browser: 1`.

Every write to the page's own routes (`/ui/`, `/session/`) requires an exact
matching Origin, with or without a cookie, as does every cookie-authenticated
or `X-Identity-Browser` write. The cookie is not what makes a request a
browser's: the GitHub poll signs a browser in without one, and a foreign page
able to post it could sign its visitor in to the foreign author's account.
Responses carry `Referrer-Policy: same-origin` rather than `no-referrer`,
because under `no-referrer` a browser sends `Origin: null` on the page's plain
form posts (sign out, Discord) and the check refuses them; other origins get
no referrer either way. The CSP's `form-action` names Discord's authorize
origin when Discord is configured, because a browser holds the redirect that
answers the Discord form post to that directive and refuses it otherwise.

The page is server-rendered HTML (`internal/api/web/page.html`) with htmx
fragments under `/ui/`, built on the same operations the JSON API uses so the
two cannot diverge. htmx runs from the embedded file with eval disabled under
the CSP; Tailwind compiles `input.css` and the templates to a committed
`style.css` that CI rebuilds. A consuming service's authorize request is
finished server-side on `/authorize` the moment there is a session for it, and
kept in a short-lived cookie across the sign-in otherwise. Tokens and handoff
codes are not placed in URLs except for the short-lived one-time callback code.

## Application handoff

An application redirects to `/authorize` with `redirect_uri`, `state`, and
optionally an S256 `code_challenge`. Browser consumers should always supply PKCE.
The identity page mints a single-use code for the signed-in browser;
`POST /v1/handoff` mints one for a bearer account token. The application
exchanges it server-side at `/v1/exchange`, supplying `code_verifier` when the code
was challenge-bound. Codes expire after two minutes, are bound to the callback,
and are refused if the account token that created them has been revoked.

With `prompt=none` the application only asks whether the browser is already
signed in here: if it is, the code comes back as usual; if not, the browser is
sent straight back with `error=login_required` and the state, nothing is shown
and nothing is kept. A callback off the allowlist is refused either way.

`IDENTITY_REDIRECT_ALLOW` contains allowed callback URLs. An entry ending in `/`
allows descendants on that same scheme and host; otherwise its path must match
exactly. Use exact callbacks for hosted applications. URL parsing rejects userinfo,
fragments, foreign hosts, and non-HTTPS destinations other than loopback HTTP.

Handoff tokens have an immutable audience equal to the callback origin. They can
call `/v1/whoami`, read/update their own `/v1/avatar`, revoke themselves, and
sign their browser out through `/v1/signout`.
They cannot link providers, create tokens,
list other tokens, revoke other tokens, or obtain another application handoff.
Every consumer must check `token.audience` against its own configured origin.
The audience is a constraint on identity credentials; document roles and other
application permissions remain the consumer's responsibility.

## One sign-in, every application

A token handed off from the browser signed in here records that sign-in as its
parent. That link is the whole of single sign-on and single sign-out: a browser
signed in here reaches every application without signing in again, and
revoking the sign-in, from this page's sign-out, from its token list, or from
any application through `/v1/signout`, revokes every token minted from it in
the same transaction. An application's `/v1/signout` revokes its token's parent,
so one sign-out ends the browser's session here and at every application it
reached; sessions another browser started are untouched. A browser signing in
to the same application again replaces the token its sign-in last got there,
which is what bounds application tokens.

A code asked for through `POST /v1/handoff` with a bearer account token becomes
a token with no parent: a deliberate machine credential for a script. Nothing a
browser does replaces or revokes it, nor does revoking the account token that
asked for it; only its own revocation or expiry ends it. Tokens minted before
the link existed have no parent either.

Account tokens obtained directly through sign-in or explicitly minted through
token management retain account-management rights. A CLI may deliberately accept
these operator credentials. Browser-facing applications should accept only their
own audience-bound tokens, kept server-side behind a separate session cookie.

## Storage and lifecycle

Profile photos belong to the shared identity account. The database keeps the
private asset key and original dimensions; asset service owns the original
bytes and background renditions. A scoped server credential always uploads
with private visibility. Reads choose the smallest sufficient image using both
dimensions, validate its storage origin, and stream it without forwarding the
asset credential or exposing its signed URL. There is no public photo route.
Application tokens can change their own account's photo, an explicit shared
profile capability that does not grant provider or credential management.

Uploads accept JPEG, PNG and WebP only. They are capped at 5 MiB, 16 megapixels,
8192 pixels per side, six attempts per account per hour, and one concurrent
image decode/upload. Full decoding happens before storage. Original bytes are
preserved exactly, while the asset service's resized images serve UI displays.
Removing or replacing a photo changes its reference; immutable assets remain
private. Account metadata and provider proofs remain the only profile fields.

One Go binary and SQLite database, WAL, one database connection. Accounts,
provider identities, and hashed tokens are durable. Pending provider flows and
handoff codes are in memory; a restart costs an unfinished sign-in one retry.
Tokens expire after 90 days and live account tokens are capped at 25 per
account. Application tokens do not count toward the cap, so a busy browser can
never lock an account out of signing in; the ones a browser sign-in mints are
bounded by replacement instead. Application sessions may impose a shorter
lifetime.

The audience schema migration revokes existing tokens named `handoff ...`, since
those older credentials carried account-wide authority. Browser consumers sign
in again once. Other account tokens and machine credentials remain valid.

The parent migration adds a column with a default, and every statement names
its columns, so the binary before it keeps working on a migrated database: it
mints tokens without a parent and revokes without the cascade.

## Deliberately absent

- Automatic matching by email and account merging. Merging needs proof of both
  accounts and a deliberate policy for each consumer's existing data.
- Third-party clients, OIDC discovery, consent screens, and a general OAuth
  authorization server. Revisit a standard identity provider before adding them.
- Application roles or data permissions. Groups say who; consumers say what.
- Nested groups. Flatten server-side if it is ever needed; the wire shape stays.

## Layout

- `api`: the OpenAPI contract and the generated Go client.
- `client`: the package a consuming Go service imports.
- `cmd/identityd`: environment configuration, process lifecycle, operator commands.
- `internal/api`: HTTP API, browser sessions, provider flows, handoffs, groups, the page.
- `internal/api/web`: templates, Tailwind input and output, vendored htmx.
- `internal/avatar`: scoped private asset-service uploads and rendition delivery.
- `internal/provider`: GitHub and Discord exchanges.
- `internal/store`: accounts, identities, tokens, groups and migrations.
- `internal/token`: random opaque credentials and hashing.
