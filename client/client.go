// Package client is how a Go service signs people in through identity and
// asks who they are. It is the security rules as code you import, so the
// next service cannot forget one:
//
//   - the browser is sent to identity's /authorize with a PKCE challenge and
//     comes back to /auth/callback with a one-time code;
//   - the code is exchanged server-side for an application token, which is
//     kept sealed inside an HttpOnly cookie and never reaches the browser;
//   - every whoami answer is checked against this service's own origin
//     (token.audience) before it is trusted, and re-checked with identity
//     every Recheck, so revoking at identity takes effect within minutes;
//   - what a group grants is this service's decision, made with who.In.
//
// Wire it up:
//
//	auth, err := client.New(client.Config{
//		IdentityURL: "https://identity.example",
//		BaseURL:     "https://app.example",   // this service's public origin
//		Key:         key,                     // 32 random bytes, from the environment
//	})
//	auth.Routes(mux)                          // /auth/signin, /auth/callback, /auth/signout, /auth/me
//	mux.Handle("/admin/", auth.RequireGroup("basically-core", adminHandler))
//	mux.Handle("/", auth.Require(pageHandler))
//
// and in a handler behind Require, client.WhoFrom(r.Context()) is the person.
//
// There is no session table. The cookie holds the application token sealed
// with AES-GCM under Key, so a leaked database reveals no sessions and a
// rotated Key signs everyone out. The cost is that "sign out everywhere" is
// done at identity, by revoking the tokens named for this service.
package client

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/basicallysource/identity/api"
)

// Config is everything a consuming service has to say.
type Config struct {
	// IdentityURL is where identity lives, e.g. https://identity.example.
	IdentityURL string
	// BaseURL is this service's public origin, e.g. https://app.example.
	// It is the audience every token must carry, and the callback
	// (BaseURL + CallbackPath) must be on identity's redirect allowlist.
	// Only https, or http on localhost.
	BaseURL string
	// Key seals the session cookie. Exactly 32 random bytes, kept in the
	// environment; rotating it signs everybody out.
	Key []byte
	// CallbackPath is where identity sends the browser back. Default
	// /auth/callback.
	CallbackPath string
	// Cookie is the session cookie's name. Default __Host-session on https
	// and session on localhost. Set it when two services share a host.
	Cookie string
	// SessionTTL is how long a sign-in lasts here, at most the token's own
	// life. Default 30 days.
	SessionTTL time.Duration
	// Recheck is how long a whoami answer is trusted before identity is
	// asked again: the window in which a revocation or a group change is
	// not yet seen. Default 5 minutes.
	Recheck time.Duration
	// HTTPClient talks to identity. Default: a 10-second timeout.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

// Identity is one provider's proof of the account.
type Identity struct {
	Provider string
	// ID is the provider's immutable id: GitHub's number, Discord's snowflake.
	ID     string
	Handle string
}

// Avatar describes the account's chosen profile picture.
type Avatar struct {
	ID            string
	Width, Height int
	Source        string
}

// Who is the signed-in person, as identity last described them.
type Who struct {
	Account    string
	Handle     string
	Groups     []string
	Identities []Identity
	Avatar     *Avatar
	// TokenID names the application token behind this session, for the
	// audit trail and for revoking it.
	TokenID   string
	ExpiresAt time.Time
}

// In reports whether the person is in a group. This is the whole
// authorization API: a service decides what a name means and asks this.
func (w Who) In(group string) bool {
	for _, g := range w.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// Identity returns the account's proof at a provider, if it has one.
func (w Who) Identity(provider string) (Identity, bool) {
	for _, i := range w.Identities {
		if i.Provider == provider {
			return i, true
		}
	}
	return Identity{}, false
}

// Auth is a configured client. One per service.
type Auth struct {
	cfg    Config
	api    *api.ClientWithResponses
	aead   cipher.AEAD
	secure bool

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	who     Who
	checked time.Time
}

// New validates the configuration and refuses to run a service on a bad
// one, because every field here is a security setting.
func New(cfg Config) (*Auth, error) {
	cfg.IdentityURL = strings.TrimRight(cfg.IdentityURL, "/")
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.IdentityURL == "" || cfg.BaseURL == "" {
		return nil, errors.New("identity client: IdentityURL and BaseURL are required")
	}
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Host == "" || base.Path != "" || base.RawQuery != "" {
		return nil, errors.New("identity client: BaseURL must be an origin like https://app.example")
	}
	secure := base.Scheme == "https"
	if !secure && !(base.Scheme == "http" && (base.Hostname() == "localhost" || base.Hostname() == "127.0.0.1")) {
		return nil, errors.New("identity client: BaseURL must be https, or http on localhost")
	}
	if len(cfg.Key) != 32 {
		return nil, errors.New("identity client: Key must be exactly 32 bytes")
	}
	block, err := aes.NewCipher(cfg.Key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if cfg.CallbackPath == "" {
		cfg.CallbackPath = "/auth/callback"
	}
	if !strings.HasPrefix(cfg.CallbackPath, "/") {
		return nil, errors.New("identity client: CallbackPath must start with /")
	}
	if cfg.Cookie == "" {
		cfg.Cookie = "session"
		if secure {
			cfg.Cookie = "__Host-session"
		}
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}
	if cfg.Recheck <= 0 {
		cfg.Recheck = 5 * time.Minute
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	c, err := api.NewClientWithResponses(cfg.IdentityURL, api.WithHTTPClient(cfg.HTTPClient))
	if err != nil {
		return nil, err
	}
	return &Auth{cfg: cfg, api: c, aead: aead, secure: secure, cache: map[string]cached{}}, nil
}

// Routes installs the four routes this package owns.
func (a *Auth) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/signin", a.signin)
	mux.HandleFunc("GET "+a.cfg.CallbackPath, a.callback)
	mux.HandleFunc("POST /auth/signout", a.signout)
	mux.HandleFunc("GET /auth/me", a.me)
}

// SignInURL is where to send a browser to sign in and come back to dest,
// a path on this service.
func (a *Auth) SignInURL(dest string) string {
	return "/auth/signin?dest=" + url.QueryEscape(localPath(dest))
}

func (a *Auth) callbackURL() string { return a.cfg.BaseURL + a.cfg.CallbackPath }

// -- cookies -------------------------------------------------------------

func (a *Auth) seal(v any) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, a.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(a.aead.Seal(nonce, nonce, plain, []byte(a.cfg.BaseURL))), nil
}

func (a *Auth) unseal(value string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < a.aead.NonceSize() {
		return errors.New("bad cookie")
	}
	plain, err := a.aead.Open(nil, raw[:a.aead.NonceSize()], raw[a.aead.NonceSize():], []byte(a.cfg.BaseURL))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	maxAge := int(ttl.Seconds())
	if value == "" {
		maxAge = -1
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode})
}

// session is what the session cookie holds.
type session struct {
	Token  string    `json:"t"`
	Issued time.Time `json:"i"`
}

// pending is what the sign-in cookie holds across the round trip.
type pending struct {
	State    string `json:"s"`
	Verifier string `json:"v"`
	Dest     string `json:"d"`
}

func (a *Auth) signinCookie() string { return a.cfg.Cookie + "-signin" }

// -- the round trip ------------------------------------------------------

func (a *Auth) signin(w http.ResponseWriter, r *http.Request) {
	state, err := randomString(16)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	verifier, err := randomString(32)
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	sealed, err := a.seal(pending{State: state, Verifier: verifier, Dest: localPath(r.URL.Query().Get("dest"))})
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	a.setCookie(w, a.signinCookie(), sealed, 10*time.Minute)

	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{
		"redirect_uri":   {a.callbackURL()},
		"state":          {state},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])},
	}
	http.Redirect(w, r, a.cfg.IdentityURL+"/authorize?"+q.Encode(), http.StatusSeeOther)
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(a.signinCookie())
	var p pending
	if err != nil || a.unseal(c.Value, &p) != nil || p.State == "" {
		a.fail(w, http.StatusBadRequest, "this sign-in did not start here; start again")
		return
	}
	a.setCookie(w, a.signinCookie(), "", 0)
	if subtle.ConstantTimeCompare([]byte(p.State), []byte(r.URL.Query().Get("state"))) != 1 {
		a.fail(w, http.StatusBadRequest, "this sign-in did not start here; start again")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.fail(w, http.StatusBadRequest, "no code; start again")
		return
	}

	exchanged, err := a.api.ExchangeWithResponse(r.Context(), api.ExchangeJSONRequestBody{
		Code: code, RedirectUri: a.callbackURL(), CodeVerifier: &p.Verifier,
	})
	if err != nil {
		a.cfg.Logger.Error("identity client: exchange", "error", err)
		a.fail(w, http.StatusBadGateway, "sign-in is unavailable; try again")
		return
	}
	if exchanged.JSON201 == nil || exchanged.JSON201.Token == "" {
		a.fail(w, http.StatusForbidden, "that sign-in is not valid; start again")
		return
	}
	token := exchanged.JSON201.Token

	who, err := a.whoami(r.Context(), token)
	if err != nil {
		// The token was minted; do not leave it live for nothing.
		a.revoke(r.Context(), token)
		a.cfg.Logger.Warn("identity client: refused a sign-in", "error", err)
		a.fail(w, http.StatusForbidden, "that sign-in is not valid; start again")
		return
	}

	ttl := a.cfg.SessionTTL
	if !who.ExpiresAt.IsZero() && time.Until(who.ExpiresAt) < ttl {
		ttl = time.Until(who.ExpiresAt)
	}
	sealed, err := a.seal(session{Token: token, Issued: time.Now()})
	if err != nil {
		a.fail(w, http.StatusInternalServerError, "could not start the session")
		return
	}
	a.setCookie(w, a.cfg.Cookie, sealed, ttl)
	a.remember(token, who)
	http.Redirect(w, r, localPath(p.Dest), http.StatusSeeOther)
}

func (a *Auth) signout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		a.fail(w, http.StatusForbidden, "sign-out must come from this site")
		return
	}
	if token, ok := a.token(r); ok {
		a.revoke(r.Context(), token)
		a.forget(token)
	}
	a.setCookie(w, a.cfg.Cookie, "", 0)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// me is the JSON a page's own script asks: who is signed in, if anyone,
// and where to go if not. The shape is the one contract a frontend helper
// in any language relies on.
func (a *Auth) me(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	who, ok := a.Who(r)
	if !ok {
		json.NewEncoder(w).Encode(map[string]any{"signed_in": false, "signin": a.SignInURL(r.Referer())})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"signed_in": true,
		"account":   who.Account,
		"handle":    who.Handle,
		"groups":    who.Groups,
		"avatar":    who.Avatar,
		"signout":   "/auth/signout",
	})
}

// -- who is asking -------------------------------------------------------

// Who resolves the request's session to the person behind it, asking
// identity at most once per Recheck per session. false means signed out,
// expired, or revoked.
func (a *Auth) Who(r *http.Request) (Who, bool) {
	token, ok := a.token(r)
	if !ok {
		return Who{}, false
	}
	if who, ok := a.recall(token); ok {
		return who, true
	}
	who, err := a.whoami(r.Context(), token)
	if err != nil {
		a.forget(token)
		return Who{}, false
	}
	a.remember(token, who)
	return who, true
}

func (a *Auth) token(r *http.Request) (string, bool) {
	c, err := r.Cookie(a.cfg.Cookie)
	if err != nil || c.Value == "" {
		return "", false
	}
	var s session
	if a.unseal(c.Value, &s) != nil || s.Token == "" {
		return "", false
	}
	return s.Token, true
}

// whoami asks identity and applies the one check every consumer must:
// the token was minted for this service and no other.
func (a *Auth) whoami(ctx context.Context, token string) (Who, error) {
	resp, err := a.api.WhoamiWithResponse(ctx, bearer(token))
	if err != nil {
		return Who{}, err
	}
	if resp.JSON200 == nil {
		return Who{}, fmt.Errorf("identity answered %d", resp.StatusCode())
	}
	me := resp.JSON200
	if me.Token.Audience != a.cfg.BaseURL {
		return Who{}, fmt.Errorf("token audience is %q, not this service", me.Token.Audience)
	}
	if me.Token.ExpiresAt != nil && me.Token.ExpiresAt.Before(time.Now()) {
		return Who{}, errors.New("token expired")
	}
	who := Who{Account: string(me.Account), Handle: me.Handle, Groups: []string{}, TokenID: me.Token.Id}
	for _, g := range me.Groups {
		who.Groups = append(who.Groups, string(g))
	}
	for _, i := range me.Identities {
		who.Identities = append(who.Identities, Identity{Provider: string(i.Provider), ID: i.Id, Handle: i.Handle})
	}
	if me.Avatar != nil {
		who.Avatar = &Avatar{ID: me.Avatar.Id, Width: me.Avatar.Width, Height: me.Avatar.Height, Source: me.Avatar.Source}
	}
	if me.Token.ExpiresAt != nil {
		who.ExpiresAt = *me.Token.ExpiresAt
	}
	return who, nil
}

func (a *Auth) revoke(ctx context.Context, token string) {
	resp, err := a.api.WhoamiWithResponse(ctx, bearer(token))
	if err != nil || resp.JSON200 == nil {
		return
	}
	a.api.RevokeTokenWithResponse(ctx, resp.JSON200.Token.Id, bearer(token))
}

func bearer(token string) api.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+token)
		return nil
	}
}

// The cache: token hash to the last answer, trusted for Recheck.

func cacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (a *Auth) recall(token string) (Who, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.cache[cacheKey(token)]
	if !ok || time.Since(c.checked) > a.cfg.Recheck {
		return Who{}, false
	}
	return c.who, true
}

func (a *Auth) remember(token string, who Who) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) > 4096 {
		for k, c := range a.cache {
			if time.Since(c.checked) > a.cfg.Recheck {
				delete(a.cache, k)
			}
		}
	}
	a.cache[cacheKey(token)] = cached{who: who, checked: time.Now()}
}

func (a *Auth) forget(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cache, cacheKey(token))
}

// -- gates ---------------------------------------------------------------

type whoKey struct{}

// WhoFrom is the person behind a request that passed Require or
// RequireGroup.
func WhoFrom(ctx context.Context) (Who, bool) {
	who, ok := ctx.Value(whoKey{}).(Who)
	return who, ok
}

// Require lets only signed-in people through, and puts them in the
// context. A browser asking for a page is sent to sign in and brought back;
// anything else gets 401.
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := a.Who(r)
		if !ok {
			if _, err := r.Cookie(a.cfg.Cookie); err == nil {
				a.setCookie(w, a.cfg.Cookie, "", 0)
			}
			if wantsPage(r) {
				http.Redirect(w, r, a.SignInURL(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			a.fail(w, http.StatusUnauthorized, "sign in required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), whoKey{}, who)))
	})
}

// RequireGroup is Require plus membership of one group. A signed-in person
// outside it gets 403 and is told which group would let them in.
func (a *Auth) RequireGroup(group string, next http.Handler) http.Handler {
	return a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := WhoFrom(r.Context())
		if !who.In(group) {
			a.fail(w, http.StatusForbidden, "this needs membership of "+group)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// -- small things --------------------------------------------------------

func (a *Auth) sameOrigin(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == a.cfg.BaseURL
	}
	return r.Header.Get("Sec-Fetch-Site") == "same-origin"
}

func (a *Auth) fail(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, message)
}

// localPath keeps a destination on this service: a path, never a URL, so a
// sign-in cannot be used to bounce a browser somewhere else.
func localPath(dest string) string {
	if dest == "" || !strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "//") || strings.HasPrefix(dest, "/\\") {
		return "/"
	}
	return dest
}

func wantsPage(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") &&
		r.Header.Get("HX-Request") == ""
}

func randomString(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
