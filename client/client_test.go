package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/basicallysource/identity/internal/api"
	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
	"github.com/basicallysource/identity/internal/token"
)

// The whole round trip against the real identity server: a browser that
// is signed in at identity is sent there by the app, comes back with a
// code, and ends up with a sealed session the app trusts.

type harness struct {
	t        *testing.T
	identity *httptest.Server
	server   *api.Server
	app      *httptest.Server
	auth     *Auth
	cookies  map[string]*http.Cookie
	logs     *logs
	// account token of the signed-in person at identity; empty is a browser
	// nobody is signed in to identity with
	identityToken   string
	identityTokenID string
	accountID       string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	server := &api.Server{Store: db, GitHub: &provider.GitHub{}, Discord: &provider.Discord{}}
	identity := httptest.NewServer(server.Handler())
	t.Cleanup(identity.Close)
	server.BaseURL = identity.URL

	// A person who has signed in at identity: an account and a live
	// account token, which the browser holds as identity's own cookie.
	account, err := db.SignIn(context.Background(), "github", "583231", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	minted, id, hash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertToken(context.Background(), store.Token{ID: id, SecretHash: hash, AccountID: account.ID, Name: "sign-in", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, identity: identity, server: server, cookies: map[string]*http.Cookie{}, identityToken: minted, identityTokenID: id, accountID: account.ID}
	h.startApp()
	// The app's origin is only known once its listener exists; identity
	// allows the callback afterwards.
	server.RedirectAllow = []string{h.app.URL + "/auth/callback"}
	return h
}

// startApp is the consuming service, pointed at h.identity.
func (h *harness) startApp() {
	key := make([]byte, 32)
	rand.Read(key)
	mux := http.NewServeMux()
	h.app = httptest.NewServer(mux)
	h.t.Cleanup(h.app.Close)
	h.logs = &logs{}
	var err error
	h.auth, err = New(Config{IdentityURL: h.identity.URL, BaseURL: h.app.URL, Key: key, Recheck: 50 * time.Millisecond, Logger: slog.New(slog.NewTextHandler(h.logs, nil))})
	if err != nil {
		h.t.Fatal(err)
	}
	h.auth.Routes(mux)
	mux.Handle("/secret", h.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := WhoFrom(r.Context())
		io.WriteString(w, "hello "+who.Handle)
	})))
	// What a handler finds for TokenFrom, behind the gate and outside it.
	tokenFrom := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := TokenFrom(r.Context())
		json.NewEncoder(w).Encode(map[string]any{"token": token, "ok": ok})
	})
	mux.Handle("/token", h.auth.Require(tokenFrom))
	mux.Handle("/open", tokenFrom)
	mux.Handle("/admin", h.auth.RequireGroup("core", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "admin")
	})))
}

// get is the browser: keeps cookies per host, never follows redirects.
func (h *harness) get(rawURL string, headers map[string]string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("Accept", "text/html")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.addCookies(req)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	h.keepCookies(req, resp)
	return resp
}

func (h *harness) post(rawURL string, headers map[string]string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(""))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.addCookies(req)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	h.keepCookies(req, resp)
	return resp
}

func (h *harness) addCookies(req *http.Request) {
	for key, c := range h.cookies {
		if strings.HasPrefix(key, req.URL.Host+"|") {
			req.AddCookie(c)
		}
	}
	if req.URL.Host == mustHost(h.identity.URL) && h.identityToken != "" {
		req.AddCookie(&http.Cookie{Name: "identity_session", Value: h.identityToken})
	}
}

func (h *harness) keepCookies(req *http.Request, resp *http.Response) {
	for _, c := range resp.Cookies() {
		key := req.URL.Host + "|" + c.Name
		if c.MaxAge < 0 || c.Value == "" {
			delete(h.cookies, key)
		} else {
			h.cookies[key] = c
		}
	}
}

// cookie is what the browser holds for the app under a name.
func (h *harness) cookie(name string) (*http.Cookie, bool) {
	c, ok := h.cookies[mustHost(h.app.URL)+"|"+name]
	return c, ok
}

// plantSession gives the browser a session for a token without the round
// trip, for an identity that cannot do one.
func (h *harness) plantSession(token string) {
	h.t.Helper()
	sealed, err := h.auth.seal(session{Token: token, Issued: time.Now()})
	if err != nil {
		h.t.Fatal(err)
	}
	h.cookies[mustHost(h.app.URL)+"|session"] = &http.Cookie{Name: "session", Value: sealed}
}

func (h *harness) me(headers map[string]string) map[string]any {
	h.t.Helper()
	resp := h.get(h.app.URL+"/auth/me", headers)
	var me map[string]any
	if err := json.Unmarshal([]byte(body(resp)), &me); err != nil {
		h.t.Fatalf("/auth/me answered %d: %v", resp.StatusCode, err)
	}
	return me
}

// logs is everything the app logged, safe to read while it serves.
type logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// request is the browser's next request to the app, as a handler would get
// it, for calling Auth directly.
func (h *harness) request() *http.Request {
	req := httptest.NewRequest(http.MethodGet, h.app.URL+"/", nil)
	h.addCookies(req)
	return req
}

func mustHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Host
}

func body(resp *http.Response) string {
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

// signIn walks the round trip and leaves the browser with an app session.
func (h *harness) signIn(dest string) *http.Response {
	h.t.Helper()
	// 1. The app sends the browser to identity.
	resp := h.get(h.app.URL+dest, nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/auth/signin?dest=") {
		h.t.Fatalf("protected page while signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = h.get(h.app.URL+resp.Header.Get("Location"), nil)
	authorize := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(authorize, h.identity.URL+"/authorize?") {
		h.t.Fatalf("signin: %d %q", resp.StatusCode, authorize)
	}
	q, _ := url.Parse(authorize)
	if q.Query().Get("code_challenge") == "" || q.Query().Get("state") == "" || q.Query().Get("redirect_uri") != h.app.URL+"/auth/callback" {
		h.t.Fatalf("authorize request is missing something: %s", authorize)
	}
	// 2. Identity, which has the person signed in, sends the browser back.
	resp = h.get(authorize, nil)
	callback := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(callback, h.app.URL+"/auth/callback?") {
		h.t.Fatalf("identity authorize: %d %q %s", resp.StatusCode, callback, body(resp))
	}
	// 3. The app exchanges the code and starts a session.
	return h.get(callback, nil)
}

func TestRoundTrip(t *testing.T) {
	h := newHarness(t)
	resp := h.signIn("/secret")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/secret" {
		t.Fatalf("callback: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body(resp))
	}
	cookieName := "session"
	c, ok := h.cookies[mustHost(h.app.URL)+"|"+cookieName]
	if !ok || !c.HttpOnly {
		t.Fatalf("no HttpOnly session cookie: %+v", h.cookies)
	}
	if strings.Contains(c.Value, "bsid_") {
		t.Fatal("the token is in the cookie in the clear")
	}
	if _, ok := h.cookies[mustHost(h.app.URL)+"|"+cookieName+"-signin"]; ok {
		t.Fatal("the sign-in cookie outlived the callback")
	}

	resp = h.get(h.app.URL+"/secret", nil)
	if resp.StatusCode != http.StatusOK || body(resp) != "hello octocat" {
		t.Fatalf("secret after sign-in: %d", resp.StatusCode)
	}

	// /auth/me is the shape a frontend relies on.
	resp = h.get(h.app.URL+"/auth/me", nil)
	var me map[string]any
	json.Unmarshal([]byte(body(resp)), &me)
	if me["signed_in"] != true || me["handle"] != "octocat" || me["groups"] == nil {
		t.Fatalf("me = %v", me)
	}

	// Groups gate: refused until granted, then let in after the recheck.
	resp = h.get(h.app.URL+"/admin", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body(resp), "core") {
		t.Fatalf("admin before the grant: %d", resp.StatusCode)
	}
	if err := h.server.Store.CreateGroup(context.Background(), "core", "", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := h.server.Store.AddMember(context.Background(), "core", h.accountID, "cli"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	resp = h.get(h.app.URL+"/admin", nil)
	if resp.StatusCode != http.StatusOK || body(resp) != "admin" {
		t.Fatalf("admin after the grant: %d", resp.StatusCode)
	}

	// Sign out ends the sign-in at identity, and the application token with
	// it; the old cookie is dead even if replayed.
	old := h.cookies[mustHost(h.app.URL)+"|"+cookieName]
	resp = h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": h.app.URL})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signout: %d", resp.StatusCode)
	}
	if _, ok := h.cookies[mustHost(h.app.URL)+"|"+cookieName]; ok {
		t.Fatal("session cookie survived sign-out")
	}
	h.cookies[mustHost(h.app.URL)+"|"+cookieName] = old
	time.Sleep(60 * time.Millisecond)
	resp = h.get(h.app.URL+"/secret", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a replayed cookie after sign-out answered %d", resp.StatusCode)
	}
}

func TestRevocationAtIdentityIsSeenWithinRecheck(t *testing.T) {
	h := newHarness(t)
	h.signIn("/secret")
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret: %d", resp.StatusCode)
	}
	// Revoke every application token for this account at identity.
	tokens, _ := h.server.Store.TokensFor(context.Background(), h.accountID)
	for _, tk := range tokens {
		if tk.Audience != "" {
			h.server.Store.RevokeToken(context.Background(), h.accountID, tk.ID)
		}
	}
	// Still trusted inside the window...
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret right after revocation: %d", resp.StatusCode)
	}
	// ...and not after it.
	time.Sleep(60 * time.Millisecond)
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("secret after the recheck: %d", resp.StatusCode)
	}
}

func TestCallbackRefusesAForeignState(t *testing.T) {
	h := newHarness(t)
	h.get(h.app.URL+"/auth/signin?dest=/secret", nil)
	resp := h.get(h.app.URL+"/auth/callback?code=x&state=forged", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state answered %d", resp.StatusCode)
	}
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a session appeared anyway: %d", resp.StatusCode)
	}
}

func TestSignOutRequiresSameOrigin(t *testing.T) {
	h := newHarness(t)
	h.signIn("/secret")
	resp := h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-site sign-out answered %d", resp.StatusCode)
	}
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("session was lost to a cross-site sign-out: %d", resp.StatusCode)
	}
}

func TestDestinationStaysLocal(t *testing.T) {
	for dest, want := range map[string]string{
		"/":                        "/",
		"/secret":                  "/secret",
		"/admin?x=1#y":             "/admin?x=1#y",
		"/docs/a%20b?q=c%2Fd":      "/docs/a%20b?q=c%2Fd",
		"/a/..//evil.example":      "/a/..//evil.example",
		"":                         "/",
		"secret":                   "/",
		"https://evil.example/":    "/",
		"http:evil.example":        "/",
		"javascript:alert(1)":      "/",
		"//evil.example":           "/",
		"///evil.example":          "/",
		"/\\evil.example":          "/",
		"\\\\evil.example":         "/",
		"/x\\y":                    "/",
		"/?next=\\evil.example":    "/",
		"/\t/evil.example":         "/",
		"/%09/evil.example":        "/",
		"/\r\n/evil.example":       "/",
		"/%0d%0a/evil.example":     "/",
		"/x\nSet-Cookie: a=b":      "/",
		"/\x7f/evil.example":       "/",
		"/\u0085/evil.example":     "/",
		"/%2F/evil.example":        "/",
		"/%5Cevil.example":         "/",
		" /evil.example":           "/",
		"/%zz":                     "/",
		"//user@evil.example/":     "/",
		"https://app.example/page": "/",
	} {
		if got := localPath(dest); got != want {
			t.Errorf("localPath(%q) = %q, want %q", dest, got, want)
		}
	}

	// End to end: the tab arrives decoded, and the person lands at the root.
	h := newHarness(t)
	resp := h.signIn("/secret")
	if resp.Header.Get("Location") != "/secret" {
		t.Fatalf("dest %q", resp.Header.Get("Location"))
	}
	resp = h.get(h.app.URL+"/auth/signin?dest=/%09/evil.example", nil)
	resp = h.get(resp.Header.Get("Location"), nil)
	resp = h.get(resp.Header.Get("Location"), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("a hostile dest came back as %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSilentSignInWhenSignedInAtIdentity(t *testing.T) {
	h := newHarness(t)
	// A mark left from earlier in the browser session goes once signed in.
	h.cookies[mustHost(h.app.URL)+"|session-silent"] = &http.Cookie{Name: "session-silent", Value: "1"}

	resp := h.get(h.app.URL+h.auth.SilentSignInURL("/secret"), nil)
	authorize, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || authorize.Query().Get("prompt") != "none" || authorize.Query().Get("code_challenge") == "" {
		t.Fatalf("silent signin: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = h.get(authorize.String(), nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.Contains(resp.Header.Get("Location"), "code=") {
		t.Fatalf("identity with a session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = h.get(resp.Header.Get("Location"), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/secret" {
		t.Fatalf("callback: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body(resp))
	}
	if _, ok := h.cookie("session-silent"); ok {
		t.Fatal("the silent mark outlived a sign-in")
	}
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret after a silent sign-in: %d", resp.StatusCode)
	}
}

func TestSilentSignInWithNobodyAtIdentity(t *testing.T) {
	h := newHarness(t)
	token := h.identityToken
	h.identityToken = ""

	// The page's script is offered the silent sign-in, back to its page.
	me := h.me(map[string]string{"Referer": h.app.URL + "/secret?tab=2"})
	if me["signed_in"] != false || me["signin"] != h.auth.SignInURL("/secret?tab=2") || me["silent_signin"] != h.auth.SilentSignInURL("/secret?tab=2") {
		t.Fatalf("me while signed out = %v", me)
	}
	resp := h.get(h.app.URL+me["silent_signin"].(string), nil)
	resp = h.get(resp.Header.Get("Location"), nil)
	callback, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || callback.Query().Get("error") != "login_required" || callback.Query().Get("state") == "" {
		t.Fatalf("identity with nobody signed in: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = h.get(callback.String(), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/secret?tab=2" {
		t.Fatalf("login_required callback: %d %q %s", resp.StatusCode, resp.Header.Get("Location"), body(resp))
	}
	mark, ok := h.cookie("session-silent")
	if !ok || !mark.HttpOnly || mark.Path != "/" || mark.SameSite != http.SameSiteLaxMode || mark.MaxAge != 0 || !mark.Expires.IsZero() {
		t.Fatalf("silent mark: %+v", mark)
	}
	if _, ok := h.cookie("session"); ok {
		t.Fatal("a session appeared from a sign-in that found nobody")
	}
	if _, ok := h.cookie("session-signin"); ok {
		t.Fatal("the sign-in cookie outlived the callback")
	}

	// Marked, the page shows its button and is not offered another try.
	me = h.me(nil)
	if me["signed_in"] != false || me["signin"] == nil || me["silent_signin"] != nil {
		t.Fatalf("me after a silent miss = %v", me)
	}

	// Signing in with the button clears the mark.
	h.identityToken = token
	if resp := h.signIn("/secret"); resp.Header.Get("Location") != "/secret" {
		t.Fatalf("sign-in after a silent miss: %d", resp.StatusCode)
	}
	if _, ok := h.cookie("session-silent"); ok {
		t.Fatal("the silent mark outlived a sign-in")
	}
}

func TestLoginRequiredNeedsTheState(t *testing.T) {
	h := newHarness(t)
	h.get(h.app.URL+h.auth.SilentSignInURL("/secret"), nil)
	resp := h.get(h.app.URL+"/auth/callback?error=login_required&state=forged", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login_required with a forged state answered %d", resp.StatusCode)
	}

	// Only a silent sign-in may come back without one.
	delete(h.cookies, mustHost(h.app.URL)+"|session-silent")
	resp = h.get(h.app.URL+h.auth.SignInURL("/secret"), nil)
	authorize, _ := url.Parse(resp.Header.Get("Location"))
	if authorize.Query().Get("prompt") != "" {
		t.Fatalf("a sign-in with a button asked for prompt: %s", authorize)
	}
	resp = h.get(h.app.URL+"/auth/callback?error=login_required&state="+url.QueryEscape(authorize.Query().Get("state")), nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("login_required for a sign-in with a button answered %d", resp.StatusCode)
	}
	if _, ok := h.cookie("session-silent"); ok {
		t.Fatal("login_required marked a browser that did not ask silently")
	}
}

// A silent sign-in is tried once a browser session however it ends. An
// identity that is down never sends the browser back, and neither does one
// from before prompt=none, which shows its sign-in page instead.
func TestSilentSignInIsTriedOnce(t *testing.T) {
	h, fake := newFakeHarness(t)
	me := h.me(nil)
	if me["signed_in"] != false || me["silent_signin"] == nil {
		t.Fatalf("me while signed out = %v", me)
	}
	fake.Close()
	resp := h.get(h.app.URL+me["silent_signin"].(string), nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), fake.URL+"/authorize?") {
		t.Fatalf("silent signin: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, err := http.Get(resp.Header.Get("Location")); err == nil {
		resp.Body.Close()
		t.Fatal("identity answered")
	}
	if me := h.me(nil); me["signed_in"] != false || me["signin"] == nil || me["silent_signin"] != nil {
		t.Fatalf("me after a silent sign-in that never came back = %v", me)
	}
}

func TestSignOutEndsTheSignInAtIdentity(t *testing.T) {
	h := newHarness(t)
	h.signIn("/secret")
	resp := h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": h.app.URL})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("signout: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	stored, err := h.server.Store.TokenByID(context.Background(), h.identityTokenID)
	if err != nil || stored.RevokedAt.IsZero() {
		t.Fatalf("the identity sign-in survived signing out of the app: %+v %v", stored, err)
	}
	// Marked, so the page cannot sign straight back in silently.
	if _, ok := h.cookie("session-silent"); !ok {
		t.Fatal("sign-out did not mark the browser")
	}
	if me := h.me(nil); me["signed_in"] != false || me["silent_signin"] != nil {
		t.Fatalf("me after sign-out = %v", me)
	}
}

func TestSignOutWithIdentityDown(t *testing.T) {
	h, fake := newFakeHarness(t)
	h.plantSession("bsid_app")
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret: %d", resp.StatusCode)
	}
	resp := h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": h.app.URL})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("signout: %d", resp.StatusCode)
	}
	if got := fake.calls("signout"); len(got) != 1 || got[0] != "Bearer bsid_app" {
		t.Fatalf("identity was asked to sign out %v", got)
	}

	h.plantSession("bsid_app")
	fake.Close()
	resp = h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": h.app.URL})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("signout with identity unreachable: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok := h.cookie("session"); ok {
		t.Fatal("the session survived signing out while identity was down")
	}
	if _, ok := h.cookie("session-silent"); !ok {
		t.Fatal("sign-out did not mark the browser")
	}
}

// An identity that will not sign the browser out, such as one from before
// /v1/signout, which refuses an application token, still ends this
// service's own token. One that did, or had already let the token go, is
// not asked twice.
func TestSignOutAtAnIdentityThatRefuses(t *testing.T) {
	h, fake := newFakeHarness(t)
	signOut := func(answer int) {
		t.Helper()
		fake.setSignOut(answer)
		h.plantSession("bsid_app")
		if resp := h.post(h.app.URL+"/auth/signout", map[string]string{"Origin": h.app.URL}); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("signout with identity answering %d: %d", answer, resp.StatusCode)
		}
		if _, ok := h.cookie("session"); ok {
			t.Fatalf("the session survived signing out with identity answering %d", answer)
		}
	}
	for _, answer := range []int{http.StatusNoContent, http.StatusUnauthorized} {
		signOut(answer)
		if got := fake.calls("revoke"); len(got) != 0 {
			t.Fatalf("identity answered %d and the token was revoked as well %v", answer, got)
		}
	}
	for i, answer := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		signOut(answer)
		if got := fake.calls("revoke"); len(got) != i+1 || got[i] != "Bearer bsid_app" {
			t.Fatalf("identity answered %d and the token was revoked %v", answer, got)
		}
	}
}

func TestIdentityOutageKeepsTheSession(t *testing.T) {
	h, fake := newFakeHarness(t)
	h.plantSession("bsid_app")
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret: %d", resp.StatusCode)
	}

	for name, answer := range map[string]int{"a 5xx": http.StatusBadGateway, "no answer": 0} {
		fake.set(answer, h.app.URL)
		time.Sleep(60 * time.Millisecond)
		for _, accept := range []string{"text/html", "application/json"} {
			resp := h.get(h.app.URL+"/secret", map[string]string{"Accept": accept})
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("%s, %s: %d %q", name, accept, resp.StatusCode, resp.Header.Get("Location"))
			}
			for _, c := range resp.Cookies() {
				t.Fatalf("%s: a cookie was touched: %+v", name, c)
			}
		}
		if resp := h.get(h.app.URL+"/auth/me", nil); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s: /auth/me answered %d", name, resp.StatusCode)
		}
		if _, err := h.auth.WhoToken(context.Background(), "bsid_app"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: WhoToken = %v", name, err)
		}
	}

	// The outage is logged, and the token is not.
	if logged := h.logs.String(); !strings.Contains(logged, "identity client: whoami") || strings.Contains(logged, "bsid_app") {
		t.Fatalf("logs during the outage: %s", logged)
	}

	// Identity back, the same session works.
	fake.set(http.StatusOK, h.app.URL)
	if resp := h.get(h.app.URL+"/secret", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("secret after the outage: %d", resp.StatusCode)
	}

	// A no is a no: 401, or a token for somebody else, ends the session.
	for name, set := range map[string]func(){
		"401":            func() { fake.set(http.StatusUnauthorized, h.app.URL) },
		"other audience": func() { fake.set(http.StatusOK, "https://other.example") },
	} {
		h.plantSession("bsid_app")
		set()
		time.Sleep(60 * time.Millisecond)
		resp := h.get(h.app.URL+"/secret", nil)
		if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/auth/signin?") {
			t.Fatalf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
		}
		if _, ok := h.cookie("session"); ok {
			t.Fatalf("%s: the session cookie was kept", name)
		}
		if _, err := h.auth.WhoToken(context.Background(), "bsid_app"); !errors.Is(err, ErrSignedOut) {
			t.Fatalf("%s: WhoToken = %v", name, err)
		}
	}
}

// Between the exchange and whoami, identity failing is an outage and saying
// no is a refusal. Neither starts a session.
func TestCallbackWhenWhoamiFails(t *testing.T) {
	h, fake := newFakeHarness(t)
	for name, c := range map[string]struct {
		status   int
		audience string
		want     int
	}{
		"a 5xx":          {http.StatusBadGateway, h.app.URL, http.StatusBadGateway},
		"no answer":      {0, h.app.URL, http.StatusBadGateway},
		"401":            {http.StatusUnauthorized, h.app.URL, http.StatusForbidden},
		"other audience": {http.StatusOK, "https://other.example", http.StatusForbidden},
	} {
		fake.set(http.StatusOK, h.app.URL)
		resp := h.get(h.app.URL+h.auth.SignInURL("/secret"), nil)
		authorize, _ := url.Parse(resp.Header.Get("Location"))
		fake.set(c.status, c.audience)
		resp = h.get(h.app.URL+"/auth/callback?code=c&state="+url.QueryEscape(authorize.Query().Get("state")), nil)
		if resp.StatusCode != c.want {
			t.Fatalf("%s: callback answered %d, want %d", name, resp.StatusCode, c.want)
		}
		if _, ok := h.cookie("session"); ok {
			t.Fatalf("%s: a session started", name)
		}
	}
}

func TestWhoTokenForBearerCallers(t *testing.T) {
	h := newHarness(t)
	h.signIn("/secret")
	c, _ := h.cookie("session")
	var s session
	if err := h.auth.unseal(c.Value, &s); err != nil {
		t.Fatal(err)
	}
	who, err := h.auth.WhoToken(context.Background(), s.Token)
	if err != nil || who.Handle != "octocat" || who.Account != h.accountID {
		t.Fatalf("WhoToken(app token) = %+v, %v", who, err)
	}
	// identity's own account token is not this service's to accept.
	for name, tk := range map[string]string{"account token": h.identityToken, "garbage": "bsid_nope", "empty": ""} {
		if _, err := h.auth.WhoToken(context.Background(), tk); !errors.Is(err, ErrSignedOut) {
			t.Errorf("WhoToken(%s) = %v", name, err)
		}
	}
}

func TestTokenFromBehindTheGateOnly(t *testing.T) {
	h := newHarness(t)
	tokenAt := func(path string) (string, bool) {
		t.Helper()
		resp := h.get(h.app.URL+path, nil)
		var got struct {
			Token string
			OK    bool
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body(resp)), &got) != nil {
			t.Fatalf("%s answered %d", path, resp.StatusCode)
		}
		return got.Token, got.OK
	}
	if token, ok := TokenFrom(context.Background()); ok || token != "" {
		t.Fatalf("TokenFrom outside any request = %q, %v", token, ok)
	}
	if token, ok := tokenAt("/open"); ok || token != "" {
		t.Fatalf("TokenFrom while signed out = %q, %v", token, ok)
	}

	h.signIn("/token")
	c, _ := h.cookie("session")
	var s session
	if err := h.auth.unseal(c.Value, &s); err != nil {
		t.Fatal(err)
	}
	token, ok := tokenAt("/token")
	if !ok || token != s.Token {
		t.Fatalf("TokenFrom behind Require = %q, %v", token, ok)
	}
	// It is the person's token for this service, which identity accepts.
	who, err := h.auth.WhoToken(context.Background(), token)
	if err != nil || who.Handle != "octocat" {
		t.Fatalf("WhoToken(TokenFrom) = %+v, %v", who, err)
	}
	// A handler outside the gate gets nothing, even with a live session.
	if token, ok := tokenAt("/open"); ok || token != "" {
		t.Fatalf("TokenFrom outside Require = %q, %v", token, ok)
	}
	if raw, _ := json.Marshal(who); strings.Contains(string(raw), token) {
		t.Fatal("the token is in Who")
	}
}

func TestCheckTellsSignedOutFromUnavailable(t *testing.T) {
	h, fake := newFakeHarness(t)
	if _, err := h.auth.Check(h.request()); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("no session: %v", err)
	}
	h.cookies[mustHost(h.app.URL)+"|session"] = &http.Cookie{Name: "session", Value: "forged"}
	if _, err := h.auth.Check(h.request()); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("a forged cookie: %v", err)
	}

	h.plantSession("bsid_app")
	if who, err := h.auth.Check(h.request()); err != nil || who.Handle != "octocat" {
		t.Fatalf("signed in: %+v, %v", who, err)
	}
	for name, answer := range map[string]int{"a 5xx": http.StatusBadGateway, "no answer": 0} {
		fake.set(answer, h.app.URL)
		time.Sleep(60 * time.Millisecond)
		if _, err := h.auth.Check(h.request()); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrSignedOut) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, ok := h.auth.Who(h.request()); ok {
			t.Fatalf("%s: Who said yes", name)
		}
	}
	for name, set := range map[string]func(){
		"401":            func() { fake.set(http.StatusUnauthorized, h.app.URL) },
		"other audience": func() { fake.set(http.StatusOK, "https://other.example") },
	} {
		set()
		time.Sleep(60 * time.Millisecond)
		if _, err := h.auth.Check(h.request()); !errors.Is(err, ErrSignedOut) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSilentMarkOnHTTPS(t *testing.T) {
	auth, err := New(Config{IdentityURL: "https://id.example", BaseURL: "https://app.example", Key: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	auth.Routes(mux)
	req := httptest.NewRequest(http.MethodPost, "https://app.example/auth/signout", nil)
	req.Header.Set("Origin", "https://app.example")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	var mark *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-session-silent" {
			mark = c
		}
	}
	if mark == nil || !mark.Secure || !mark.HttpOnly || mark.Path != "/" || mark.Domain != "" || mark.SameSite != http.SameSiteLaxMode || mark.MaxAge != 0 || !mark.Expires.IsZero() {
		t.Fatalf("silent mark on https: %+v", mark)
	}
	if got := auth.SilentSignInURL("/admin?x=1"); got != "/auth/signin?dest=%2Fadmin%3Fx%3D1&prompt=none" {
		t.Fatalf("SilentSignInURL = %q", got)
	}
}

// fakeIdentity is identity doing what a test needs it to: answering whoami
// with a chosen status and audience, or not at all, exchanging any code, and
// recording sign-outs and revocations.
type fakeIdentity struct {
	*httptest.Server
	mu       sync.Mutex
	status   int // 0 drops the connection
	audience string
	signout  int // what /v1/signout answers
	log      map[string][]string
}

func newFakeHarness(t *testing.T) (*harness, *fakeIdentity) {
	t.Helper()
	fake := &fakeIdentity{status: http.StatusOK, signout: http.StatusNoContent, log: map[string][]string{}}
	fake.Server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.Close)
	h := &harness{t: t, identity: fake.Server, cookies: map[string]*http.Cookie{}}
	h.startApp()
	fake.set(http.StatusOK, h.app.URL)
	return h, fake
}

func (f *fakeIdentity) set(status int, audience string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.audience = status, audience
}

func (f *fakeIdentity) setSignOut(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signout = status
}

func (f *fakeIdentity) calls(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.log[name]
}

func (f *fakeIdentity) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Method + " " + r.URL.Path {
	case "POST /v1/signout":
		f.log["signout"] = append(f.log["signout"], r.Header.Get("Authorization"))
		w.WriteHeader(f.signout)
	case "DELETE /v1/tokens/t1":
		f.log["revoke"] = append(f.log["revoke"], r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	case "POST /v1/exchange":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"token":"bsid_app","account":"3f9c2a81d04b","handle":"octocat"}`)
	case "GET /v1/whoami":
		switch f.status {
		case 0:
			panic(http.ErrAbortHandler)
		case http.StatusOK:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"account": "3f9c2a81d04b", "handle": "octocat", "created_at": time.Now(),
				"identities": []any{}, "groups": []string{},
				"token": map[string]any{"id": "t1", "name": "handoff", "audience": f.audience, "created_at": time.Now()},
			})
		default:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.status)
			io.WriteString(w, `{"error":"no"}`)
		}
	default:
		http.NotFound(w, r)
	}
}

func TestNewRefusesBadConfiguration(t *testing.T) {
	key := make([]byte, 32)
	for name, cfg := range map[string]Config{
		"no identity":  {BaseURL: "https://app.example", Key: key},
		"no base":      {IdentityURL: "https://id.example", Key: key},
		"short key":    {IdentityURL: "https://id.example", BaseURL: "https://app.example", Key: key[:16]},
		"http base":    {IdentityURL: "https://id.example", BaseURL: "http://app.example", Key: key},
		"base w/ path": {IdentityURL: "https://id.example", BaseURL: "https://app.example/app", Key: key},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(Config{IdentityURL: "https://id.example", BaseURL: "http://localhost:8860", Key: key}); err != nil {
		t.Errorf("localhost refused: %v", err)
	}
}
