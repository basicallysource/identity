package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
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
	// account token of the signed-in person at identity
	identityToken string
	accountID     string
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

	h := &harness{t: t, identity: identity, server: server, cookies: map[string]*http.Cookie{}, identityToken: minted, accountID: account.ID}

	key := make([]byte, 32)
	rand.Read(key)
	// The app's origin is only known once its listener exists; identity
	// allows the callback afterwards.
	mux := http.NewServeMux()
	h.app = httptest.NewServer(mux)
	t.Cleanup(h.app.Close)
	h.auth, err = New(Config{IdentityURL: identity.URL, BaseURL: h.app.URL, Key: key, Recheck: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	h.auth.Routes(mux)
	mux.Handle("/secret", h.auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := WhoFrom(r.Context())
		io.WriteString(w, "hello "+who.Handle)
	})))
	mux.Handle("/admin", h.auth.RequireGroup("core", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "admin")
	})))
	server.RedirectAllow = []string{h.app.URL + "/auth/callback"}
	return h
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
	if req.URL.Host == mustHost(h.identity.URL) {
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

	// Sign out revokes the application token at identity; the old cookie
	// is dead even if replayed.
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
	h := newHarness(t)
	resp := h.signIn("/secret")
	if resp.Header.Get("Location") != "/secret" {
		t.Fatalf("dest %q", resp.Header.Get("Location"))
	}
	for _, bad := range []string{"https://evil.example/", "//evil.example", "/\\evil.example", "secret", ""} {
		if got := localPath(bad); got != "/" {
			t.Errorf("localPath(%q) = %q", bad, got)
		}
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
