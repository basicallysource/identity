package api

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/basicallysource/identity/internal/token"
	"net/http"
	"net/http/httptest"
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
