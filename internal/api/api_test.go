package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
)

// fakeGitHub is github.com boiled down to the three requests the device flow
// makes: a code, a redemption, a who-is-this.
func fakeGitHub(t *testing.T, id int64, login string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"device_code":"dev-1","user_code":"ABCD-1234","verification_uri":"https://example.invalid/device","expires_in":900,"interval":1}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"gh-token"}`)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gh-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"id":%d,"login":%q}`, id, login)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

// fakeDiscord is discord.com boiled down to the redemption and the who-is-this.
func fakeDiscord(t *testing.T, id, username string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"dc-token"}`)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dc-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprintf(w, `{"id":%q,"username":%q}`, id, username)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	github := fakeGitHub(t, 583231, "octocat")
	discord := fakeDiscord(t, "80351110224678912", "nelly")

	server := &Server{
		Store: db,
		GitHub: &provider.GitHub{
			ClientID:  "test-client",
			DeviceURL: github.URL + "/device",
			TokenURL:  github.URL + "/token",
			UserURL:   github.URL + "/user",
		},
		Discord: &provider.Discord{
			ClientID:     "discord-client",
			ClientSecret: "discord-secret",
			TokenURL:     discord.URL + "/token",
			UserURL:      discord.URL + "/me",
		},
	}
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	server.BaseURL = ts.URL
	return ts, server
}

func post(t *testing.T, url, bearer, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func decode[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// githubSignIn walks the whole device flow and returns the minted token.
func githubSignIn(t *testing.T, ts *httptest.Server) tokenResponse {
	t.Helper()
	start := post(t, ts.URL+"/signin/github/start", "", "")
	if start.StatusCode != http.StatusOK {
		t.Fatalf("start answered %d", start.StatusCode)
	}
	device := decode[provider.Device](t, start)

	finish := post(t, ts.URL+"/signin/github/finish", "",
		fmt.Sprintf(`{"device_code":%q}`, device.DeviceCode))
	if finish.StatusCode != http.StatusCreated {
		t.Fatalf("finish answered %d", finish.StatusCode)
	}
	return decode[tokenResponse](t, finish)
}

func TestGitHubSignInAndWhoami(t *testing.T) {
	ts, _ := newTestServer(t)
	minted := githubSignIn(t, ts)
	if minted.Token == "" || minted.Handle != "octocat" {
		t.Fatalf("unexpected mint %+v", minted)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("whoami answered %d", resp.StatusCode)
	}
	me := decode[whoamiResponse](t, resp)
	if me.Account != minted.Account || len(me.Identities) != 1 || me.Identities[0].Provider != "github" {
		t.Fatalf("unexpected whoami %+v", me)
	}

	// A second sign-in is the same account, not a new one.
	again := githubSignIn(t, ts)
	if again.Account != minted.Account {
		t.Fatalf("second sign-in made account %s, expected %s", again.Account, minted.Account)
	}
}

// discordCallbackPage runs start + callback and returns the final page body.
func discordCallbackPage(t *testing.T, ts *httptest.Server, bearer string) string {
	t.Helper()
	start := post(t, ts.URL+"/signin/discord/start", bearer, "")
	if start.StatusCode != http.StatusOK {
		t.Fatalf("discord start answered %d", start.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range start.Cookies() {
		if c.Name == "identity_state" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("discord start set no state cookie")
	}
	body := decode[map[string]string](t, start)

	authorize, err := url.Parse(body["url"])
	if err != nil {
		t.Fatal(err)
	}
	state := authorize.Query().Get("state")
	if state == "" {
		t.Fatal("authorize URL carries no state")
	}
	if got := authorize.Query().Get("redirect_uri"); got != ts.URL+"/signin/discord/callback" {
		t.Fatalf("redirect_uri is %q", got)
	}

	req, _ := http.NewRequest(http.MethodGet,
		ts.URL+"/signin/discord/callback?code=any&state="+state, nil)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	return string(page)
}

func TestDiscordSignInAndLink(t *testing.T) {
	ts, _ := newTestServer(t)

	// A fresh Discord sign-in mints a token the page stores.
	page := discordCallbackPage(t, ts, "")
	match := regexp.MustCompile(`bsid_[A-Za-z0-9_-]+_[A-Za-z0-9_-]+`).FindString(page)
	if match == "" {
		t.Fatalf("callback page carries no token:\n%s", page)
	}

	// A GitHub account linking Discord: same Discord identity now belongs to
	// the first account, so the link must be refused.
	minted := githubSignIn(t, ts)
	page = discordCallbackPage(t, ts, minted.Token)
	if !strings.Contains(page, "different account") {
		t.Fatalf("expected the link to be refused:\n%s", page)
	}

	// A different Discord identity would link fine; prove the plumbing with
	// a fresh service where nobody owns the Discord identity yet.
	ts2, _ := newTestServer(t)
	minted2 := githubSignIn(t, ts2)
	page = discordCallbackPage(t, ts2, minted2.Token)
	if !strings.Contains(page, "signed in") {
		t.Fatalf("expected a completed link:\n%s", page)
	}

	req, _ := http.NewRequest(http.MethodGet, ts2.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+minted2.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	me := decode[whoamiResponse](t, resp)
	if len(me.Identities) != 2 {
		t.Fatalf("expected 2 identities after the link, got %+v", me.Identities)
	}
}

func TestCallbackRefusesForeignState(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/signin/discord/callback?code=any&state=forged")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(page), "did not start here") {
		t.Fatalf("a forged state was not refused:\n%s", page)
	}
}

func TestTokenLifecycle(t *testing.T) {
	ts, _ := newTestServer(t)
	minted := githubSignIn(t, ts)

	// Mint a named token, see both listed, revoke the new one, and watch it
	// stop working.
	resp := post(t, ts.URL+"/v1/tokens", minted.Token, `{"name":"ci"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint answered %d", resp.StatusCode)
	}
	second := decode[tokenResponse](t, resp)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+second.Token)
	listResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	list := decode[struct {
		Tokens []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Current bool   `json:"current"`
		} `json:"tokens"`
	}](t, listResp)
	if len(list.Tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %+v", list.Tokens)
	}
	var secondID string
	for _, row := range list.Tokens {
		if row.Name == "ci" {
			secondID = row.ID
			if !row.Current {
				t.Fatal("the bearer's own token is not marked current")
			}
		}
	}

	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/v1/tokens/"+secondID, nil)
	req.Header.Set("Authorization", "Bearer "+minted.Token)
	revokeResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke answered %d", revokeResp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+second.Token)
	deadResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if deadResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revoked token still answered %d", deadResp.StatusCode)
	}
}

func TestClientAddrTrustsOnlyTheConfiguredHeader(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.9:4242"
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")

	// Unconfigured, the header is attacker-controlled noise.
	if got := server.clientAddr(req); got != "10.0.0.9" {
		t.Fatalf("unconfigured clientAddr = %q", got)
	}

	server.ClientIPHeader = "CF-Connecting-IP"
	if got := server.clientAddr(req); got != "203.0.113.7" {
		t.Fatalf("configured clientAddr = %q", got)
	}

	// A chain-style value names the client first.
	server.ClientIPHeader = "X-Forwarded-For"
	req.Header.Set("X-Forwarded-For", "198.51.100.4, 172.19.0.2")
	if got := server.clientAddr(req); got != "198.51.100.4" {
		t.Fatalf("chained clientAddr = %q", got)
	}
}

func TestHandoffAndExchange(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{"https://tracker.example/"}
	minted := githubSignIn(t, ts)

	callback := "https://tracker.example/auth/callback"

	// A destination outside the allowlist is refused.
	refused := post(t, ts.URL+"/v1/handoff", minted.Token,
		`{"redirect_uri":"https://evil.example/steal"}`)
	refused.Body.Close()
	if refused.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign destination answered %d", refused.StatusCode)
	}

	// An allowed one mints a code, and the exchange mints a service token.
	resp := post(t, ts.URL+"/v1/handoff", minted.Token,
		fmt.Sprintf(`{"redirect_uri":%q}`, callback))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handoff answered %d", resp.StatusCode)
	}
	code := decode[map[string]string](t, resp)["code"]

	// Spending it correctly works exactly once.
	exchanged := post(t, ts.URL+"/v1/exchange", "",
		fmt.Sprintf(`{"code":%q,"redirect_uri":%q}`, code, callback))
	if exchanged.StatusCode != http.StatusCreated {
		t.Fatalf("exchange answered %d", exchanged.StatusCode)
	}
	service := decode[tokenResponse](t, exchanged)
	if service.Account != minted.Account || service.Token == minted.Token {
		t.Fatalf("exchange minted %+v for account %s", service, minted.Account)
	}
	again := post(t, ts.URL+"/v1/exchange", "",
		fmt.Sprintf(`{"code":%q,"redirect_uri":%q}`, code, callback))
	again.Body.Close()
	if again.StatusCode != http.StatusForbidden {
		t.Fatalf("a spent code answered %d", again.StatusCode)
	}

	// A code spent against the wrong redirect fails AND burns: any attempt
	// consumes it, so a probing thief costs the person one retry, never a
	// session.
	resp = post(t, ts.URL+"/v1/handoff", minted.Token,
		fmt.Sprintf(`{"redirect_uri":%q}`, callback))
	second := decode[map[string]string](t, resp)["code"]
	wrong := post(t, ts.URL+"/v1/exchange", "",
		fmt.Sprintf(`{"code":%q,"redirect_uri":"https://tracker.example/other"}`, second))
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched redirect answered %d", wrong.StatusCode)
	}
	burned := post(t, ts.URL+"/v1/exchange", "",
		fmt.Sprintf(`{"code":%q,"redirect_uri":%q}`, second, callback))
	burned.Body.Close()
	if burned.StatusCode != http.StatusForbidden {
		t.Fatalf("a burned code answered %d", burned.StatusCode)
	}

	// The service token is a real credential.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+service.Token)
	who, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	me := decode[whoamiResponse](t, who)
	if me.Account != minted.Account {
		t.Fatalf("service token belongs to %s, want %s", me.Account, minted.Account)
	}
}
