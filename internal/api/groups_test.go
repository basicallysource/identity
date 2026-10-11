package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/basicallysource/identity/internal/store"
)

func do(t *testing.T, method, url, bearer, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
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

func status(t *testing.T, resp *http.Response) int {
	t.Helper()
	resp.Body.Close()
	return resp.StatusCode
}

// makeAdmin is the CLI's job done directly against the store: the first
// administrator cannot be made through the API, because nobody is one yet.
func makeAdmin(t *testing.T, server *Server, accountID string) {
	t.Helper()
	ctx := context.Background()
	if err := server.Store.CreateGroup(ctx, store.AdminGroup, "", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := server.Store.AddMember(ctx, store.AdminGroup, accountID, "cli"); err != nil {
		t.Fatal(err)
	}
}

func TestWhoamiCarriesGroups(t *testing.T) {
	ts, server := newTestServer(t)
	minted := githubSignIn(t, ts)

	me := decode[whoamiResponse](t, do(t, "GET", ts.URL+"/v1/whoami", minted.Token, ""))
	if me.Groups == nil || len(me.Groups) != 0 {
		t.Fatalf("groups should be an empty list, got %#v", me.Groups)
	}

	makeAdmin(t, server, minted.Account)
	me = decode[whoamiResponse](t, do(t, "GET", ts.URL+"/v1/whoami", minted.Token, ""))
	if len(me.Groups) != 1 || me.Groups[0] != store.AdminGroup {
		t.Fatalf("groups = %v", me.Groups)
	}
}

func TestGroupAdministrationIsForAdminsOnly(t *testing.T) {
	ts, server := newTestServer(t)
	minted := githubSignIn(t, ts)

	// Signed in but not an admin: every route refuses with 403, and the
	// refusal is not a 404 that would hide whether the route exists.
	for _, probe := range []struct{ method, path string }{
		{"GET", "/v1/groups"},
		{"POST", "/v1/groups"},
		{"GET", "/v1/groups/audit"},
		{"GET", "/v1/groups/core"},
		{"DELETE", "/v1/groups/core"},
		{"PUT", "/v1/groups/core/members/000000000000"},
		{"DELETE", "/v1/groups/core/members/000000000000"},
		{"GET", "/v1/accounts?q=a"},
	} {
		if got := status(t, do(t, probe.method, ts.URL+probe.path, minted.Token, `{"name":"core"}`)); got != http.StatusForbidden {
			t.Errorf("%s %s answered %d for a non-admin", probe.method, probe.path, got)
		}
		if got := status(t, do(t, probe.method, ts.URL+probe.path, "", `{"name":"core"}`)); got != http.StatusUnauthorized {
			t.Errorf("%s %s answered %d signed out", probe.method, probe.path, got)
		}
	}

	// An application token held by an administrator is still refused:
	// administration is done signed in here, never through a consumer.
	makeAdmin(t, server, minted.Account)
	server.RedirectAllow = []string{"https://app.example/"}
	code := decode[map[string]string](t, post(t, ts.URL+"/v1/handoff", minted.Token, `{"redirect_uri":"https://app.example/cb"}`))["code"]
	app := decode[tokenResponse](t, post(t, ts.URL+"/v1/exchange", "", fmt.Sprintf(`{"code":%q,"redirect_uri":"https://app.example/cb"}`, code)))
	if got := status(t, do(t, "GET", ts.URL+"/v1/groups", app.Token, "")); got != http.StatusForbidden {
		t.Fatalf("an application token reached group administration: %d", got)
	}
}

func TestGroupAdministration(t *testing.T) {
	ts, server := newTestServer(t)
	admin := githubSignIn(t, ts)
	makeAdmin(t, server, admin.Account)
	// A second, ordinary account to put in groups.
	other, err := server.Store.SignIn(context.Background(), "discord", "77", "nelly")
	if err != nil {
		t.Fatal(err)
	}

	created := do(t, "POST", ts.URL+"/v1/groups", admin.Token, `{"name":"core","description":"the company"}`)
	if created.StatusCode != http.StatusCreated {
		t.Fatalf("create answered %d", created.StatusCode)
	}
	if g := decode[groupBody](t, created); g.Name != "core" || g.CreatedBy != admin.Account || g.Members != 0 {
		t.Fatalf("created %+v", g)
	}
	if got := status(t, do(t, "POST", ts.URL+"/v1/groups", admin.Token, `{"name":"core"}`)); got != http.StatusConflict {
		t.Fatalf("duplicate answered %d", got)
	}
	if got := status(t, do(t, "POST", ts.URL+"/v1/groups", admin.Token, `{"name":"Not Valid"}`)); got != http.StatusBadRequest {
		t.Fatalf("bad name answered %d", got)
	}

	// Find nelly by handle, add her, see her, and see it in the audit.
	found := decode[struct {
		Accounts []accountBody `json:"accounts"`
	}](t, do(t, "GET", ts.URL+"/v1/accounts?q=nel", admin.Token, ""))
	if len(found.Accounts) != 1 || found.Accounts[0].Account != other.ID || found.Accounts[0].Identities[0].Provider != "discord" {
		t.Fatalf("search found %+v", found.Accounts)
	}
	if got := status(t, do(t, "PUT", ts.URL+"/v1/groups/core/members/"+other.ID, admin.Token, "")); got != http.StatusNoContent {
		t.Fatalf("add answered %d", got)
	}
	if got := status(t, do(t, "PUT", ts.URL+"/v1/groups/core/members/000000000000", admin.Token, "")); got != http.StatusNotFound {
		t.Fatalf("adding nobody answered %d", got)
	}
	detail := decode[groupDetailBody](t, do(t, "GET", ts.URL+"/v1/groups/core", admin.Token, ""))
	if len(detail.Members) != 1 || detail.Members[0].Handle != "nelly" || detail.Members[0].AddedBy != admin.Account {
		t.Fatalf("detail %+v", detail)
	}
	list := decode[struct {
		Groups []groupBody `json:"groups"`
	}](t, do(t, "GET", ts.URL+"/v1/groups", admin.Token, ""))
	if len(list.Groups) != 2 || list.Groups[0].Name != "core" || list.Groups[0].Members != 1 || list.Groups[1].Name != store.AdminGroup {
		t.Fatalf("list %+v", list.Groups)
	}

	// The audit names the actor for the API change and the CLI for the seed.
	audit := decode[struct {
		Entries []auditBody `json:"entries"`
	}](t, do(t, "GET", ts.URL+"/v1/groups/audit?limit=10", admin.Token, ""))
	if len(audit.Entries) != 4 || audit.Entries[0].Action != store.AuditAddMember || audit.Entries[0].Actor != admin.Account || audit.Entries[0].Handle != "nelly" {
		t.Fatalf("audit %+v", audit.Entries)
	}
	if audit.Entries[3].Actor != "cli" {
		t.Fatalf("seed not attributed to the cli: %+v", audit.Entries[3])
	}

	// Removal, the admin lockout guard, and deletion.
	if got := status(t, do(t, "DELETE", ts.URL+"/v1/groups/core/members/"+other.ID, admin.Token, "")); got != http.StatusNoContent {
		t.Fatalf("remove answered %d", got)
	}
	if got := status(t, do(t, "DELETE", ts.URL+"/v1/groups/"+store.AdminGroup+"/members/"+admin.Account, admin.Token, "")); got != http.StatusForbidden {
		t.Fatalf("the last admin removed themselves: %d", got)
	}
	if got := status(t, do(t, "DELETE", ts.URL+"/v1/groups/"+store.AdminGroup, admin.Token, "")); got != http.StatusForbidden {
		t.Fatalf("the admin group was deleted: %d", got)
	}
	if got := status(t, do(t, "DELETE", ts.URL+"/v1/groups/core", admin.Token, "")); got != http.StatusNoContent {
		t.Fatalf("delete answered %d", got)
	}
	if got := status(t, do(t, "GET", ts.URL+"/v1/groups/core", admin.Token, "")); got != http.StatusNotFound {
		t.Fatalf("a deleted group answered %d", got)
	}
}

func TestGroupReaderReadsOnlyItsGroups(t *testing.T) {
	ts, server := newTestServer(t)
	minted := githubSignIn(t, ts)
	ctx := context.Background()
	for _, group := range []string{"docs-maintainer", "basically-core"} {
		if err := server.Store.CreateGroup(ctx, group, "", "cli"); err != nil {
			t.Fatal(err)
		}
		if err := server.Store.AddMember(ctx, group, minted.Account, "cli"); err != nil {
			t.Fatal(err)
		}
	}
	secret := "reader-secret"
	readers, err := ParseGroupReaders("chatbot:" + fmt.Sprintf("%x", sha256.Sum256([]byte(secret))) + ":docs-maintainer")
	if err != nil {
		t.Fatal(err)
	}
	server.GroupReaders = readers

	// Its own group, with the members' provider ids.
	group := decode[groupDetailBody](t, do(t, "GET", ts.URL+"/v1/groups/docs-maintainer", secret, ""))
	if len(group.Members) != 1 || group.Members[0].Account != minted.Account {
		t.Fatalf("members = %#v", group.Members)
	}
	ids := group.Members[0].Identities
	if len(ids) != 1 || ids[0].Provider != "github" || ids[0].ID != "583231" {
		t.Fatalf("identities = %#v", ids)
	}

	// Nothing else: another group, the list, the log, a write.
	for _, probe := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/v1/groups/basically-core", http.StatusForbidden},
		{"GET", "/v1/groups/no-such-group", http.StatusForbidden},
		{"GET", "/v1/groups", http.StatusUnauthorized},
		{"GET", "/v1/groups/audit", http.StatusUnauthorized},
		{"DELETE", "/v1/groups/docs-maintainer", http.StatusUnauthorized},
		{"PUT", "/v1/groups/docs-maintainer/members/000000000000", http.StatusUnauthorized},
		{"GET", "/v1/whoami", http.StatusUnauthorized},
	} {
		if got := status(t, do(t, probe.method, ts.URL+probe.path, secret, "")); got != probe.want {
			t.Errorf("%s %s answered %d for a group reader, want %d", probe.method, probe.path, got, probe.want)
		}
	}

	// A wrong secret is nobody.
	if got := status(t, do(t, "GET", ts.URL+"/v1/groups/docs-maintainer", "not-the-secret", "")); got != http.StatusUnauthorized {
		t.Errorf("a wrong secret answered %d", got)
	}
}

func TestParseGroupReadersRefusesMalformedEntries(t *testing.T) {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("s")))
	for _, bad := range []string{"chatbot", "chatbot:" + hash, "chatbot:nothex:g", "chatbot:abcd:g", ":" + hash + ":g", "chatbot:" + hash + ":"} {
		if _, err := ParseGroupReaders(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	readers, err := ParseGroupReaders(" a:" + hash + ":x+y , ")
	if err != nil || len(readers) != 1 || readers[0].Name != "a" || len(readers[0].Groups) != 2 {
		t.Fatalf("readers = %#v, %v", readers, err)
	}
}
