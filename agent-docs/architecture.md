# Architecture

The committed decisions and their reasons. Change a decision, change this file
in the same commit.

## What it does

One account per human across Basically's services. A person proves who they
are at GitHub or Discord; this service records that proof against one account
and mints an opaque token. Every other service accepts that token and asks
this one who it belongs to. The other Basically services (the asset service,
hive, the bots' web surfaces) are expected to migrate their sign-in here over
time; new services start here and never grow their own.

## The one idea

Identity and authorization are different services' jobs. This service answers
exactly one question — *who is this token* — and refuses to grow opinions
about what the answer is allowed to do. Tiers, roles, quotas, and scopes live
in each consuming service, keyed by the account id this service hands out.
That is what keeps the surface small enough to trust: no consent screens, no
scopes, no delegated third-party tokens, no admin UI.

## Committed decisions

- **Build, don't self-host an IdP.** Keycloak/Authentik/Ory idle at hundreds
  of MB and instantly become the most security-critical box in the fleet with
  someone else's CVE stream attached. "Never roll your own auth" is about
  passwords and crypto; this design has neither. GitHub and Discord do the
  passwords. Tokens are 32 random bytes verified by hashed lookup —
  revocable, no signatures, no JWT expiry-vs-revocation dance.
- **Provider ids, not logins, are the identity.** An identity is keyed by the
  provider's immutable id (GitHub's numeric id, Discord's snowflake). A login
  can be renamed and re-registered by somebody else; the handle is recorded
  but only as the human-readable name at the time of the last proof.
- **Provider tokens are used once and dropped.** The GitHub/Discord access
  token proves an identity via one who-am-I call and is never stored. This
  service holds who people are, never credentials to act as them elsewhere.
- **GitHub is the device flow.** No redirect to catch, no client secret to
  keep; works identically from a browser, a terminal, or a desktop app. That
  matters because the consumers include CLIs and local apps, not just sites.
- **Discord is the redirect flow, because Discord offers nothing else.** It is
  OAuth2 but not OIDC (no id_token), so the proof is the same shape as
  GitHub's: ask `/users/@me` who the token belongs to. The one cookie in the
  system is the short-lived state cookie this flow needs.
- **Linking reuses the sign-in flows.** Any flow started with a bearer token
  attaches the proved identity to that account instead of signing in. An
  identity that already proves a different account is refused, never moved —
  account merging is a deliberate future operation, not a side effect.
- **Accounts merge by copying, services integrate by HTTP.** A consuming
  service's whole authenticator is `GET /v1/whoami`. When an existing service
  migrates here, its account rows copy over and its own authenticator becomes
  that call; nothing else about it changes.
- **One binary, one SQLite file, WAL.** The write load is humans signing in;
  a database server would be pure operational surface. Half-finished flows
  (device codes, OAuth states) live in memory and cost one retry on restart.
- **Tokens expire (90 days) and live tokens are capped (25 per account).** A
  leaked token has a horizon and "make another one" cannot go on forever. The
  page holds its token in sessionStorage, not a cookie: nothing on this
  service is an ambient credential a third party could ride.

## Not built yet, and where it goes

- **Real SSO** — one browser session across sibling sites, id_tokens, other
  people's software verifying tokens. That full OIDC-provider surface is
  where DIY becomes a liability; re-evaluate an off-the-shelf IdP at that
  point, not before. Accounts data walks over in one copy either way.
- **Account merging** — two accounts discovered to be the same human. Needs a
  deliberate flow with both proofs in hand; until then the conflict error is
  correct.
- **Service-scoped tokens** — today a token is identity-wide, which is fine
  while every consumer is ours. If third-party consumers ever appear, tokens
  grow an audience.

## Layout

    cmd/identityd        the binary: env config, wiring, shutdown
    internal/api         HTTP surface: sign-in flows, whoami, tokens, the page
    internal/api/web     the page (vanilla JS, sessionStorage token) + styles
    internal/provider    GitHub device flow, Discord redirect flow
    internal/store       SQLite: accounts, identities, tokens
    internal/token       opaque token mint/parse/hash
