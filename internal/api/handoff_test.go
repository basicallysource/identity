package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/basicallysource/identity/internal/store"
	"github.com/basicallysource/identity/internal/token"
)

const (
	docsCallback  = "https://docs.example/auth/callback"
	adminCallback = "https://admin.example/auth/callback"
)

// handOff is a service signing the browser in: /authorize, back to the
// callback with a code, the code exchanged server-side for the service's
// token.
func (b *browser) handOff(callback string) tokenResponse {
	b.t.Helper()
	status, body, header := b.page(http.MethodGet, "/authorize?"+url.Values{"redirect_uri": {callback}, "state": {"s"}}.Encode(), nil)
	location, err := url.Parse(header.Get("Location"))
	if status != http.StatusSeeOther || err != nil || location.Query().Get("code") == "" {
		b.t.Fatalf("authorize for %s: %d %q\n%s", callback, status, header.Get("Location"), body)
	}
	exchanged := post(b.t, b.base+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":%q}`, location.Query().Get("code"), callback))
	if exchanged.StatusCode != http.StatusCreated {
		b.t.Fatalf("exchange for %s answered %d", callback, exchanged.StatusCode)
	}
	return decode[tokenResponse](b.t, exchanged)
}

// machineHandOff is how a script's credential for a service is made: an
// account token asks for a code through the API and exchanges it.
func machineHandOff(t *testing.T, base, bearer, callback string) tokenResponse {
	t.Helper()
	resp := post(t, base+"/v1/handoff", bearer, fmt.Sprintf(`{"redirect_uri":%q}`, callback))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handoff answered %d", resp.StatusCode)
	}
	code := decode[map[string]string](t, resp)["code"]
	exchanged := post(t, base+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":%q}`, code, callback))
	if exchanged.StatusCode != http.StatusCreated {
		t.Fatalf("exchange answered %d", exchanged.StatusCode)
	}
	return decode[tokenResponse](t, exchanged)
}

// works checks what whoami answers for some of the named tokens.
func works(t *testing.T, base string, tokens map[string]string, want map[string]int) {
	t.Helper()
	for name, expected := range want {
		if got := status(t, do(t, http.MethodGet, base+"/v1/whoami", tokens[name], "")); got != expected {
			t.Errorf("%s: whoami answered %d, want %d", name, got, expected)
		}
	}
}

func TestSignOutAtAServiceEndsTheSignInEverywhere(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{docsCallback, adminCallback}

	b := newBrowser(t, ts)
	b.signInViaPage()
	docs := b.handOff(docsCallback)
	admin := b.handOff(adminCallback)
	// A second browser is a sign-in of its own, and a script's credential
	// made through the API belongs to no sign-in.
	other := newBrowser(t, ts)
	other.signInViaPage()
	otherDocs := other.handOff(docsCallback)
	cli := githubSignIn(t, ts)
	machine := machineHandOff(t, ts.URL, cli.Token, docsCallback)

	tokens := map[string]string{
		"docs": docs.Token, "admin": admin.Token, "session": b.cookies["identity_session"].Value,
		"other docs": otherDocs.Token, "other session": other.cookies["identity_session"].Value,
		"cli": cli.Token, "machine": machine.Token,
	}
	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/signout", docs.Token, "")); got != http.StatusNoContent {
		t.Fatalf("signout answered %d", got)
	}
	works(t, ts.URL, tokens, map[string]int{
		"docs": 401, "admin": 401, "session": 401,
		"other docs": 200, "other session": 200, "cli": 200, "machine": 200,
	})

	// The browser is signed out here too: the page is the sign-in page, and
	// the dead cookie is cleared.
	code, body, _ := b.page(http.MethodGet, "/", nil)
	if code != http.StatusOK || !strings.Contains(body, "Sign in with GitHub") {
		t.Fatalf("page after signing out at a service: %d\n%s", code, body)
	}
	if _, ok := b.cookies["identity_session"]; ok {
		t.Fatal("the dead session cookie was kept")
	}

	// A signed-out token cannot sign out again, and a token with no parent
	// signs out alone.
	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/signout", docs.Token, "")); got != http.StatusUnauthorized {
		t.Fatalf("signout with a dead token answered %d", got)
	}
	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/signout", machine.Token, "")); got != http.StatusNoContent {
		t.Fatalf("signout with a machine token answered %d", got)
	}
	works(t, ts.URL, tokens, map[string]int{"machine": 401, "cli": 200, "other docs": 200, "other session": 200})

	// Signing out is the one thing past whoami an application token may do.
	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/handoff", otherDocs.Token, `{"redirect_uri":"`+docsCallback+`"}`)); got != http.StatusForbidden {
		t.Fatalf("an application token reached handoff: %d", got)
	}
}

// The binary before the link revokes a sign-in without the tokens handed
// off from it. Signing out with one of those later is still a sign-out.
func TestSignOutWithASignInAlreadyRevoked(t *testing.T) {
	ts, server := newTestServer(t)
	account, err := server.Store.SignIn(t.Context(), "github", "583231", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_, sessionID, sessionHash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	docs, docsID, docsHash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range []store.Token{
		{ID: sessionID, SecretHash: sessionHash, AccountID: account.ID, Name: "sign-in", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RevokedAt: now},
		{ID: docsID, SecretHash: docsHash, AccountID: account.ID, Name: "handoff docs.example", Audience: "https://docs.example", ParentID: sessionID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	} {
		if err := server.Store.InsertToken(t.Context(), tk); err != nil {
			t.Fatal(err)
		}
	}
	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/signout", docs, "")); got != http.StatusNoContent {
		t.Fatalf("signout answered %d", got)
	}
	works(t, ts.URL, map[string]string{"docs": docs}, map[string]int{"docs": 401})
}

func TestSigningOutOfThisPageSignsOutOfServices(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{docsCallback}

	for _, signOut := range []struct {
		name string
		do   func(b *browser) int
	}{
		{"the sign out button", func(b *browser) int {
			status, _, _ := b.page(http.MethodPost, "/ui/signout", url.Values{})
			return status
		}},
		{"session logout", func(b *browser) int {
			status, _, _ := b.page(http.MethodPost, "/session/logout", nil)
			return status
		}},
		{"revoking this session's token", func(b *browser) int {
			me := decode[whoamiResponse](t, do(t, http.MethodGet, ts.URL+"/v1/whoami", b.cookies["identity_session"].Value, ""))
			status, _, _ := b.page(http.MethodPost, "/ui/tokens/"+me.Token.ID+"/revoke", url.Values{})
			return status
		}},
	} {
		b := newBrowser(t, ts)
		b.signInViaPage()
		docs := b.handOff(docsCallback)
		if got := signOut.do(b); got >= 400 {
			t.Fatalf("%s answered %d", signOut.name, got)
		}
		if got := status(t, do(t, http.MethodGet, ts.URL+"/v1/whoami", docs.Token, "")); got != http.StatusUnauthorized {
			t.Errorf("after %s the service's token answered %d", signOut.name, got)
		}
	}
}

// A script's credential for a service is made through the API with an
// account token, and one made before sign-ins were linked has no parent
// either. Nothing a browser does to the same service may revoke it: signing
// in to it again (which replaces that browser's own token), signing out of
// it, or the account token that asked for it being revoked.
func TestAMachineCredentialIsNeverReplaced(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{docsCallback}
	cli := githubSignIn(t, ts)
	machine := machineHandOff(t, ts.URL, cli.Token, docsCallback)
	// As the migration leaves a credential made before the link existed.
	legacy, id, hash, err := token.New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := server.Store.InsertToken(t.Context(), store.Token{ID: id, SecretHash: hash, AccountID: cli.Account, Name: "handoff docs.example", Audience: "https://docs.example", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	b := newBrowser(t, ts)
	b.signInViaPage()
	first := b.handOff(docsCallback)
	second := b.handOff(docsCallback)
	tokens := map[string]string{"machine": machine.Token, "legacy": legacy, "first": first.Token, "second": second.Token}
	// The rule does fire, on the browser's own token.
	works(t, ts.URL, tokens, map[string]int{"first": 401, "second": 200, "machine": 200, "legacy": 200})

	// The same account token asking again is a second credential, not a
	// replacement.
	again := machineHandOff(t, ts.URL, cli.Token, docsCallback)
	tokens["again"] = again.Token
	works(t, ts.URL, tokens, map[string]int{"machine": 200, "again": 200})

	if got := status(t, do(t, http.MethodPost, ts.URL+"/v1/signout", second.Token, "")); got != http.StatusNoContent {
		t.Fatalf("signout answered %d", got)
	}
	cliID, _, _ := token.Parse(cli.Token)
	if got := status(t, do(t, http.MethodDelete, ts.URL+"/v1/tokens/"+cliID, cli.Token, "")); got != http.StatusNoContent {
		t.Fatalf("revoking the account token answered %d", got)
	}
	works(t, ts.URL, tokens, map[string]int{"second": 401, "machine": 200, "again": 200, "legacy": 200})
}

func TestTheTokenCapCountsOnlyAccountTokens(t *testing.T) {
	ts, server := newTestServer(t)
	server.RedirectAllow = []string{docsCallback}
	cli := githubSignIn(t, ts)

	// Application tokens, however many, leave the account's allowance alone.
	for range maxLiveTokens + 5 {
		machineHandOff(t, ts.URL, cli.Token, docsCallback)
	}
	for range maxLiveTokens - 1 {
		if got := status(t, post(t, ts.URL+"/v1/tokens", cli.Token, `{"name":"more"}`)); got != http.StatusCreated {
			t.Fatalf("minting under the cap answered %d", got)
		}
	}
	if got := status(t, post(t, ts.URL+"/v1/tokens", cli.Token, `{"name":"one too many"}`)); got != http.StatusForbidden {
		t.Fatalf("minting over the cap answered %d", got)
	}
	// An account at its cap can still be handed off to a service.
	machineHandOff(t, ts.URL, cli.Token, docsCallback)
}
