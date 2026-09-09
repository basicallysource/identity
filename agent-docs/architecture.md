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
session, and rotating the key signs everyone out. It is tested end to end
against the real server in `internal/api`.

## Sign-in and linking

GitHub uses device flow. Discord uses its authorization-code redirect flow.
Provider access tokens are used once to fetch identity, then discarded.
Starting either flow while authenticated links that provider to the current
account. An identity already attached to another account is refused. Signing
in separately with two providers creates two accounts; there is no email-based
matching or account merge operation.

Browser sign-in uses a persistent, host-only HttpOnly cookie. HTTPS deployments
use the `__Host-identity` cookie prefix and Secure flag. Cookie-authenticated
writes require an exact matching Origin. The cookie holds an opaque account
token whose secret is stored only as a hash in SQLite. Sign-out revokes it.
The browser script does not receive that token. GitHub CLI sign-in still returns
a token; the browser requests cookie mode with `X-Identity-Browser: 1`.

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
The identity page obtains a single-use code through `/v1/handoff`. The application
exchanges it server-side at `/v1/exchange`, supplying `code_verifier` when the code
was challenge-bound. Codes expire after two minutes, are bound to the callback,
and are refused if the account token that created them has been revoked.

`IDENTITY_REDIRECT_ALLOW` contains allowed callback URLs. An entry ending in `/`
allows descendants on that same scheme and host; otherwise its path must match
exactly. Use exact callbacks for hosted applications. URL parsing rejects userinfo,
fragments, foreign hosts, and non-HTTPS destinations other than loopback HTTP.

Handoff tokens have an immutable audience equal to the callback origin. They can
call `/v1/whoami`, read/update their own `/v1/avatar`, and revoke themselves.
They cannot link providers, create tokens,
list other tokens, revoke other tokens, or obtain another application handoff.
Every consumer must check `token.audience` against its own configured origin.
The audience is a constraint on identity credentials; document roles and other
application permissions remain the consumer's responsibility.

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
Tokens expire after 90 days and live tokens are capped at 25 per account.
Application sessions may impose a shorter lifetime.

The audience schema migration revokes existing tokens named `handoff ...`, since
those older credentials carried account-wide authority. Browser consumers sign
in again once. Other account tokens and machine credentials remain valid.

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
