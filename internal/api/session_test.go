package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/basicallysource/identity/internal/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieAndCSRF(t *testing.T) {
	ts, server := newTestServer(t)
	minted := githubSignIn(t, ts)
	recorder := httptest.NewRecorder()
	server.setSession(recorder, minted.Token, *minted.ExpiresAt)
	cookie := recorder.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.Path != "/" || cookie.MaxAge < 86400 {
		t.Fatal("session is not persistent and HTTP-only")
	}
	for _, origin := range []string{"", "https://foreign.example", ts.URL} {
		req, _ := http.NewRequest("POST", ts.URL+"/session/logout", strings.NewReader(`{}`))
		req.AddCookie(cookie)
		req.Header.Set("Origin", origin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		want := 403
		if origin == ts.URL {
			want = 204
		}
		if resp.StatusCode != want {
			t.Fatalf("origin %q got %d", origin, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal("logout did not revoke token")
	}
	server.BaseURL = "https://identity.example"
	recorder = httptest.NewRecorder()
	server.setSession(recorder, "test", time.Now().Add(time.Hour))
	cookie = recorder.Result().Cookies()[0]
	if cookie.Name != "__Host-identity" || !cookie.Secure || cookie.Domain != "" {
		t.Fatal("production cookie missing host isolation")
	}
}

func TestApplicationTokenCannotManageAccount(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{"https://reader.example/auth/callback"}
	master := githubSignIn(t, ts)
	handoff := post(t, ts.URL+"/v1/handoff", master.Token, `{"redirect_uri":"https://reader.example/auth/callback"}`)
	code := decode[map[string]string](t, handoff)["code"]
	exchanged := post(t, ts.URL+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":"https://reader.example/auth/callback"}`, code))
	app := decode[tokenResponse](t, exchanged)
	for _, path := range []string{"/v1/tokens", "/v1/handoff", "/signin/github/start", "/signin/discord/start"} {
		resp := post(t, ts.URL+path, app.Token, `{}`)
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Fatalf("application token can call %s: %d", path, resp.StatusCode)
		}
	}
	req, _ := http.NewRequest("GET", ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+app.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	who := decode[whoamiResponse](t, resp)
	if who.Token.Audience != "https://reader.example" {
		t.Fatalf("wrong audience %q", who.Token.Audience)
	}
	req, _ = http.NewRequest("DELETE", ts.URL+"/v1/tokens/"+who.Token.ID, nil)
	req.Header.Set("Authorization", "Bearer "+app.Token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		t.Fatal("application cannot revoke its own token")
	}
}

func TestRedirectValidation(t *testing.T) {
	server := &Server{RedirectAllow: []string{"https://reader.example/auth/callback"}}
	for _, uri := range []string{"https://reader.example.evil/auth/callback", "https://reader.example@evil.example/auth/callback", "https://reader.example/auth/callback/evil", "https://reader.example/auth/callback#code", "http://reader.example/auth/callback", "javascript:alert(1)"} {
		if server.redirectAllowed(uri) {
			t.Fatalf("allowed %q", uri)
		}
	}
	if !server.redirectAllowed("https://reader.example/auth/callback") {
		t.Fatal("refused registered callback")
	}
}

func TestPKCEAndRevokedHandoff(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{"https://reader.example/auth/callback"}
	master := githubSignIn(t, ts)
	verifier := strings.Repeat("a", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	handoff := func() string {
		response := post(t, ts.URL+"/v1/handoff", master.Token, fmt.Sprintf(`{"redirect_uri":"https://reader.example/auth/callback","code_challenge":%q}`, challenge))
		return decode[map[string]string](t, response)["code"]
	}
	for _, proof := range []string{"wrong", verifier} {
		code := handoff()
		response := post(t, ts.URL+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":"https://reader.example/auth/callback","code_verifier":%q}`, code, proof))
		response.Body.Close()
		want := 403
		if proof == verifier {
			want = 201
		}
		if response.StatusCode != want {
			t.Fatalf("proof %q got %d", proof, response.StatusCode)
		}
	}
	code := handoff()
	id, _, _ := token.Parse(master.Token)
	server.Store.RevokeToken(t.Context(), master.Account, id)
	response := post(t, ts.URL+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":"https://reader.example/auth/callback","code_verifier":%q}`, code, verifier))
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("revoked session handoff accepted")
	}
	req, _ := http.NewRequest("POST", ts.URL+"/signin/github/start", nil)
	req.Header.Set("Origin", ts.URL)
	req.AddCookie(&http.Cookie{Name: server.sessionName(), Value: master.Token})
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("revoked cookie prevents a fresh sign-in")
	}
}

// The login CSRF this closes: the GitHub poll signs a browser in without a
// cookie, and the Origin check used to run only when one was present, so a
// foreign page could post a device code its author had approved and sign
// its visitor in to the author's account. Every page write now needs this
// service's Origin, cookie or not.
func TestPageWritesNeedTheOriginWithoutACookie(t *testing.T) {
	ts, _ := newTestServer(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// The fake GitHub has already approved dev-1: the attacker's own code.
	approved := url.Values{"device_code": {"dev-1"}, "user_code": {"ABCD-1234"}, "interval": {"1"}}.Encode()
	for _, origin := range []string{"https://evil.example", ""} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/signin/github/poll", strings.NewReader(approved))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Fatalf("a cookieless poll from origin %q answered %d with cookies %v", origin, resp.StatusCode, resp.Cookies())
		}
	}

	// The rest of the page's signed-out writes are refused the same way.
	for _, path := range []string{"/ui/signin/github", "/ui/signin/discord", "/ui/signout", "/session/logout"} {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, nil)
		req.Header.Set("Origin", "https://evil.example")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || len(resp.Cookies()) != 0 {
			t.Errorf("a cookieless %s from another origin answered %d with cookies %v", path, resp.StatusCode, resp.Cookies())
		}
	}

	// From the page itself the same poll signs in.
	b := newBrowser(t, ts)
	b.signInViaPage()

	// The page's plain form posts (sign out, Discord) work in a browser only
	// with these headers. Under no-referrer a browser sends Origin: null on
	// them, and without Discord in form-action it refuses the redirect there.
	_, _, header := b.page(http.MethodGet, "/", nil)
	if got := header.Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy is %q; the page's form posts would be refused", got)
	}
	if got := header.Get("Content-Security-Policy"); !strings.HasSuffix(got, "; form-action 'self' https://discord.com") {
		t.Fatalf("Content-Security-Policy %q does not let the Discord form reach Discord", got)
	}
}

// On https the cookies that steer a sign-in are __Host- cookies, which only
// this exact host can set. A sibling subdomain can still plant the plain
// names, so those are never read.
func TestSignInCookiesAreHostOnlyOnHTTPS(t *testing.T) {
	_, server := newTestServer(t)
	server.BaseURL = "https://identity.example"
	server.RedirectAllow = []string{"https://app.example/auth/callback"}
	handler := server.Handler()
	serve := func(req *http.Request) *http.Response {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result()
	}
	hostOnly := func(c *http.Cookie, name string) {
		t.Helper()
		if c.Name != name || c.Path != "/" || !c.Secure || c.Domain != "" || !c.HttpOnly {
			t.Fatalf("cookie %+v is not a valid %s", c, name)
		}
	}

	resp := serve(httptest.NewRequest(http.MethodGet, "/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&state=s", nil))
	if len(resp.Cookies()) != 1 {
		t.Fatalf("authorize set %v", resp.Cookies())
	}
	kept := resp.Cookies()[0]
	hostOnly(kept, "__Host-identity_authorize")
	planted := httptest.NewRequest(http.MethodGet, "/", nil)
	planted.AddCookie(&http.Cookie{Name: "identity_authorize", Value: kept.Value})
	if server.readAuthorize(planted) != nil {
		t.Fatal("a plain-named authorize cookie was read")
	}
	planted.AddCookie(kept)
	if server.readAuthorize(planted) == nil {
		t.Fatal("the __Host- authorize cookie was not read")
	}

	resp = serve(httptest.NewRequest(http.MethodPost, "/signin/discord/start", nil))
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 1 {
		t.Fatalf("discord start: %d %v", resp.StatusCode, resp.Cookies())
	}
	state := resp.Cookies()[0]
	hostOnly(state, "__Host-identity_state")
	callback := "/signin/discord/callback?code=any&state=" + url.QueryEscape(state.Value)

	req := httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(&http.Cookie{Name: "identity_state", Value: state.Value})
	resp = serve(req)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "did not start here") {
		t.Fatalf("a plain-named state cookie finished a sign-in: %d", resp.StatusCode)
	}
	req = httptest.NewRequest(http.MethodGet, callback, nil)
	req.AddCookie(state)
	resp = serve(req)
	if resp.StatusCode != http.StatusSeeOther || len(resp.Cookies()) != 1 {
		t.Fatalf("the __Host- state cookie did not finish the sign-in: %d %v", resp.StatusCode, resp.Cookies())
	}
	hostOnly(resp.Cookies()[0], "__Host-identity")
}
