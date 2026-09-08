# Architecture

Identity proves an account; each consuming application decides what that account
may read or change. An account has a random internal ID. Provider identities are
attached by immutable GitHub or Discord IDs, never by handle or email.

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

The web page exposes configured providers, provider linking, token management,
and sign-out. Scripts load from this service only. Tokens and handoff codes are
not placed in URLs except for the short-lived one-time callback code.

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
- Application roles or data permissions. Consumers own those checks.

## Layout

- `cmd/identityd`: environment configuration and process lifecycle.
- `internal/api`: HTTP API, browser sessions, provider flows, handoffs.
- `internal/api/web`: HTML, JavaScript and CSS.
- `internal/avatar`: scoped private asset-service uploads and rendition delivery.
- `internal/provider`: GitHub and Discord exchanges.
- `internal/store`: accounts, identities, tokens and migrations.
- `internal/token`: random opaque credentials and hashing.
