package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/basicallysource/identity/internal/store"
	"github.com/basicallysource/identity/internal/token"
)

// A browser for the page: keeps cookies, sends the Origin the secure
// middleware wants on a write, and does not follow redirects so a test can
// read them.
type browser struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, ts *httptest.Server) *browser {
	return &browser{t: t, base: ts.URL, cookies: map[string]*http.Cookie{}}
}

func (b *browser) do(method, path string, form url.Values) *http.Response {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, b.base+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", b.base)
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return resp
}

func (b *browser) page(method, path string, form url.Values) (int, string, http.Header) {
	b.t.Helper()
	resp := b.do(method, path, form)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw), resp.Header
}

// signInViaPage walks the GitHub device flow through the page's own
// fragments and leaves the browser holding a session cookie.
func (b *browser) signInViaPage() {
	b.t.Helper()
	status, body, _ := b.page(http.MethodPost, "/ui/signin/github", url.Values{})
	if status != http.StatusOK || !strings.Contains(body, "ABCD-1234") {
		b.t.Fatalf("device view: %d\n%s", status, body)
	}
	status, _, header := b.page(http.MethodPost, "/ui/signin/github/poll", url.Values{"device_code": {"dev-1"}, "user_code": {"ABCD-1234"}, "interval": {"1"}})
	if status != http.StatusNoContent || header.Get("HX-Redirect") != "/" {
		b.t.Fatalf("poll after approval: %d %v", status, header)
	}
	if _, ok := b.cookies["identity_session"]; !ok {
		b.t.Fatal("no session cookie after signing in through the page")
	}
}

func TestPageSignsInThroughTheDeviceFlow(t *testing.T) {
	ts, _ := newTestServer(t)
	b := newBrowser(t, ts)

	status, body, _ := b.page(http.MethodGet, "/", nil)
	if status != http.StatusOK || !strings.Contains(body, "Sign in with GitHub") || !strings.Contains(body, "Sign in with Discord") {
		t.Fatalf("signed-out page: %d\n%s", status, body)
	}
	if strings.Contains(body, "Sign out") {
		t.Fatal("signed-out page offers sign out")
	}

	b.signInViaPage()
	status, body, _ = b.page(http.MethodGet, "/", nil)
	if status != http.StatusOK || !strings.Contains(body, "Signed in as <strong>octocat</strong>") || !strings.Contains(body, "Sign out") {
		t.Fatalf("signed-in page: %d\n%s", status, body)
	}
	if strings.Contains(body, `href="/groups"`) || strings.Contains(body, "manage groups") {
		t.Fatal("a non-admin sees the groups tab")
	}
	if strings.Contains(body, b.cookies["identity_session"].Value) {
		t.Fatal("the session token is in the page")
	}

	// Static files are referenced by content hash and cached forever; any
	// other hash is 404, never a stale file.
	css := assetURL("style.css")
	if !strings.Contains(body, `href="`+css+`"`) || !strings.Contains(body, `src="`+assetURL("htmx.min.js")+`"`) {
		t.Fatalf("page does not reference the hashed assets:\n%s", body[:600])
	}
	status, body, header := b.page(http.MethodGet, css, nil)
	if status != http.StatusOK || !strings.HasPrefix(body, "/*! tailwindcss") || header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("stylesheet: %d %q", status, header.Get("Cache-Control"))
	}
	if status, _, _ := b.page(http.MethodGet, "/static/0000000000000000/style.css", nil); status != http.StatusNotFound {
		t.Fatalf("a stale asset URL answered %d", status)
	}

	// Tokens: mint one through the fragment, see it once, revoke it.
	status, body, _ = b.page(http.MethodPost, "/ui/tokens", url.Values{"name": {"laptop"}})
	if status != http.StatusOK || !strings.Contains(body, "Copy it now") || !strings.Contains(body, "laptop") {
		t.Fatalf("mint fragment: %d\n%s", status, body)
	}
	// The banner shows the token once; its id is the revoke button's.
	start := strings.Index(body, "bsid_")
	if start < 0 {
		t.Fatalf("no token in the mint fragment:\n%s", body)
	}
	minted := body[start : start+strings.Index(body[start:], "<")]
	id, _, ok := token.Parse(minted)
	if !ok || !strings.Contains(body, `hx-post="/ui/tokens/`+id+`/revoke"`) {
		t.Fatalf("no revoke button for the new token %s:\n%s", id, body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/tokens/"+id+"/revoke", url.Values{})
	if status != http.StatusOK || !strings.Contains(body, "revoked") {
		t.Fatalf("revoke fragment: %d\n%s", status, body)
	}

	// Signing out clears the cookie and the next page is the front.
	status, _, header = b.page(http.MethodPost, "/ui/signout", url.Values{})
	if status != http.StatusSeeOther || header.Get("Location") != "/" {
		t.Fatalf("sign out: %d %v", status, header)
	}
	if _, ok := b.cookies["identity_session"]; ok {
		t.Fatal("session cookie survived sign out")
	}
}

func TestPageRefusesWritesFromAnotherOrigin(t *testing.T) {
	ts, _ := newTestServer(t)
	b := newBrowser(t, ts)
	b.signInViaPage()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/ui/tokens", strings.NewReader("name=evil"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	req.AddCookie(b.cookies["identity_session"])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-site write answered %d", resp.StatusCode)
	}
}

func TestPageHandsOffToAConsumingService(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{"https://app.example/auth/callback"}
	b := newBrowser(t, ts)

	// Arriving signed out: the request is kept and the page says where the
	// person is headed.
	status, body, _ := b.page(http.MethodGet, "/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&state=xyz", nil)
	if status != http.StatusOK || !strings.Contains(body, "continue to <strong") || !strings.Contains(body, "app.example") {
		t.Fatalf("authorize while signed out: %d\n%s", status, body)
	}
	if _, ok := b.cookies[authorizeCookie]; !ok {
		t.Fatal("the authorize request was not kept")
	}

	// A destination off the allowlist is refused before anything is kept.
	status, body, _ = b.page(http.MethodGet, "/authorize?redirect_uri=https%3A%2F%2Fevil.example%2Fcb", nil)
	if status != http.StatusForbidden || !strings.Contains(body, "not handed off") {
		t.Fatalf("foreign authorize: %d\n%s", status, body)
	}
	if _, ok := b.cookies[authorizeCookie]; ok {
		t.Fatal("a refused authorize request was kept")
	}

	// Start again, sign in, and the next visit to the page completes it.
	b.page(http.MethodGet, "/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&state=xyz", nil)
	b.signInViaPage()
	status, _, header := b.page(http.MethodGet, "/", nil)
	if status != http.StatusSeeOther {
		t.Fatalf("page after sign-in with a pending authorize: %d", status)
	}
	location, err := url.Parse(header.Get("Location"))
	if err != nil || location.Host != "app.example" || location.Path != "/auth/callback" || location.Query().Get("state") != "xyz" || location.Query().Get("code") == "" {
		t.Fatalf("handoff redirect went to %q", header.Get("Location"))
	}
	if _, ok := b.cookies[authorizeCookie]; ok {
		t.Fatal("the authorize request outlived the handoff")
	}

	// The code the service receives is a real one, bound to that callback.
	exchanged := post(t, ts.URL+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":"https://app.example/auth/callback"}`, location.Query().Get("code")))
	if exchanged.StatusCode != http.StatusCreated {
		t.Fatalf("exchange answered %d", exchanged.StatusCode)
	}
	service := decode[tokenResponse](t, exchanged)
	me := decode[whoamiResponse](t, do(t, "GET", ts.URL+"/v1/whoami", service.Token, ""))
	if me.Handle != "octocat" || me.Token.Audience != "https://app.example" {
		t.Fatalf("service token describes %+v", me)
	}

	// A signed-in arrival at /authorize is one redirect, no page.
	status, _, header = b.page(http.MethodGet, "/authorize?redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fcallback&state=again", nil)
	if status != http.StatusSeeOther || !strings.Contains(header.Get("Location"), "state=again") {
		t.Fatalf("signed-in authorize: %d %q", status, header.Get("Location"))
	}
}

func TestPageGroupAdministration(t *testing.T) {
	ts, server := newTestServer(t)
	b := newBrowser(t, ts)
	b.signInViaPage()

	// Not an admin: the groups tab sends them back to the only tab they
	// have, and the fragments refuse.
	status, _, header := b.page(http.MethodGet, "/groups", nil)
	if status != http.StatusSeeOther || header.Get("Location") != "/" {
		t.Fatalf("non-admin groups tab: %d %q", status, header.Get("Location"))
	}
	status, body, _ := b.page(http.MethodPost, "/ui/groups", url.Values{"name": {"core"}})
	if status != http.StatusForbidden || !strings.Contains(body, store.AdminGroup) {
		t.Fatalf("non-admin groups fragment: %d\n%s", status, body)
	}

	// Made an admin at the terminal, the account tab grows a tab bar and
	// the groups tab is a page.
	me := decode[whoamiResponse](t, do(t, "GET", ts.URL+"/v1/whoami", b.cookies["identity_session"].Value, ""))
	makeAdmin(t, server, me.Account)
	status, body, _ = b.page(http.MethodGet, "/", nil)
	if status != http.StatusOK || !strings.Contains(body, `class="tab active" href="/"`) || !strings.Contains(body, `href="/groups"`) || !strings.Contains(body, `<li class="chip">identity-admin</li>`) || strings.Contains(body, "manage groups") {
		t.Fatalf("admin account tab: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodGet, "/groups", nil)
	if status != http.StatusOK || !strings.Contains(body, `class="tab active" href="/groups"`) || !strings.Contains(body, "manage groups") || strings.Contains(body, `id="tokens"`) {
		t.Fatalf("groups tab: %d\n%s", status, body)
	}

	// Create a group, open it, find somebody, add them, remove them, delete it.
	status, body, _ = b.page(http.MethodPost, "/ui/groups", url.Values{"name": {"Bad Name"}})
	if status != http.StatusBadRequest || !strings.Contains(body, "lowercase") {
		t.Fatalf("bad group name: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/groups", url.Values{"name": {"core"}, "description": {"the company"}})
	if status != http.StatusOK || !strings.Contains(body, ">core<") || !strings.Contains(body, "the company") || !strings.Contains(body, "0 members") {
		t.Fatalf("create group: %d\n%s", status, body)
	}
	nelly, err := server.Store.SignIn(t.Context(), "discord", "77", "nelly")
	if err != nil {
		t.Fatal(err)
	}
	status, body, _ = b.page(http.MethodGet, "/ui/accounts?q=nel&group=core", nil)
	if status != http.StatusOK || !strings.Contains(body, "nelly") || !strings.Contains(body, "/ui/groups/core/members/"+nelly.ID) {
		t.Fatalf("search: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/groups/core/members/"+nelly.ID, url.Values{})
	if status != http.StatusOK || !strings.Contains(body, "<strong>nelly</strong>") || !strings.Contains(body, "by "+me.Account) {
		t.Fatalf("add member: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodGet, "/ui/accounts?q=nel&group=core", nil)
	if !strings.Contains(body, "already in") {
		t.Fatalf("search after add does not say already in:\n%s", body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/groups/core/members/"+nelly.ID+"/remove", url.Values{})
	if status != http.StatusOK || !strings.Contains(body, "Nobody yet") {
		t.Fatalf("remove member: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/groups/"+store.AdminGroup+"/members/"+me.Account+"/remove", url.Values{})
	if status != http.StatusForbidden || !strings.Contains(body, "another administrator") {
		t.Fatalf("removing the last admin: %d\n%s", status, body)
	}
	status, body, _ = b.page(http.MethodPost, "/ui/groups/core/delete", url.Values{})
	if status != http.StatusOK || strings.Contains(body, ">core<") || !strings.Contains(body, "delete-group") {
		t.Fatalf("delete group: %d\n%s", status, body)
	}
}
