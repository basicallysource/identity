package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *DB {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestSignInCreatesOnceAndRefreshes(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	first, err := db.SignIn(ctx, "github", "583231", "octocat")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.Handle != "octocat" {
		t.Fatalf("unexpected account %+v", first)
	}

	// The same proof again, after a rename at the provider.
	again, err := db.SignIn(ctx, "github", "583231", "octocat-renamed")
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != first.ID {
		t.Fatalf("same identity made a second account: %s then %s", first.ID, again.ID)
	}

	identities, err := db.IdentitiesFor(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 1 || identities[0].Handle != "octocat-renamed" {
		t.Fatalf("identity did not refresh: %+v", identities)
	}
}

func TestLink(t *testing.T) {
	db := open(t)
	ctx := context.Background()

	account, err := db.SignIn(ctx, "github", "1", "one")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Link(ctx, account.ID, "discord", "111", "one#d"); err != nil {
		t.Fatal(err)
	}

	identities, err := db.IdentitiesFor(ctx, account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 2 {
		t.Fatalf("expected 2 identities, got %+v", identities)
	}

	// Signing in with the linked identity lands on the same account.
	viaDiscord, err := db.SignIn(ctx, "discord", "111", "one#d")
	if err != nil {
		t.Fatal(err)
	}
	if viaDiscord.ID != account.ID {
		t.Fatalf("linked identity signed into %s, expected %s", viaDiscord.ID, account.ID)
	}

	// An identity that proves somebody else cannot be linked here too.
	other, err := db.SignIn(ctx, "discord", "222", "somebody-else")
	if err != nil {
		t.Fatal(err)
	}
	err = db.Link(ctx, account.ID, "discord", "222", "somebody-else")
	if !errors.Is(err, ErrLinkedElsewhere) {
		t.Fatalf("expected ErrLinkedElsewhere, got %v", err)
	}
	_ = other
}

func TestTokens(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().UTC()

	account, err := db.SignIn(ctx, "github", "1", "one")
	if err != nil {
		t.Fatal(err)
	}

	live := Token{ID: "aaaa", SecretHash: "h", AccountID: account.ID, Name: "live",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	expired := Token{ID: "bbbb", SecretHash: "h", AccountID: account.ID, Name: "expired",
		CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	forever := Token{ID: "cccc", SecretHash: "h", AccountID: account.ID, Name: "forever",
		CreatedAt: now}
	for _, tk := range []Token{live, expired, forever} {
		if err := db.InsertToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}

	count, err := db.LiveAccountTokenCount(ctx, account.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected 2 live tokens, got %d", count)
	}

	if err := db.RevokeToken(ctx, account.ID, "aaaa"); err != nil {
		t.Fatal(err)
	}
	revoked, err := db.TokenByID(ctx, "aaaa")
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Live(now) {
		t.Fatal("revoked token still live")
	}

	// Revoking with the wrong account is a miss, not somebody else's loss.
	if err := db.RevokeToken(ctx, "not-the-owner", "cccc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// liveness checks which of an account's tokens still work.
func liveness(t *testing.T, db *DB, now time.Time, want map[string]bool) {
	t.Helper()
	for id, live := range want {
		tk, err := db.TokenByID(context.Background(), id)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if tk.Live(now) != live {
			t.Errorf("%s live = %v, want %v", id, tk.Live(now), live)
		}
	}
}

func TestRevokeTokenTakesTheTokensMintedFromIt(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account, _ := db.SignIn(ctx, "github", "1", "one")
	other, _ := db.SignIn(ctx, "github", "2", "two")

	token := func(id, audience, parent string) Token {
		return Token{ID: id, SecretHash: "h", AccountID: account.ID, Name: id, Audience: audience, ParentID: parent, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	for _, tk := range []Token{
		token("session", "", ""),
		token("docs", "https://docs.example", "session"),
		token("admin", "https://admin.example", "session"),
		token("elsewhere", "", ""),
		token("docs-elsewhere", "https://docs.example", "elsewhere"),
		token("machine", "https://docs.example", ""),
	} {
		if err := db.InsertToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	everything := map[string]bool{"session": true, "docs": true, "admin": true, "elsewhere": true, "docs-elsewhere": true, "machine": true}

	// Another account cannot reach them, and an empty id, which would name
	// every token with no parent, names none.
	if err := db.RevokeToken(ctx, other.ID, "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account's revoke: %v", err)
	}
	if err := db.RevokeToken(ctx, account.ID, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an empty id: %v", err)
	}
	liveness(t, db, now, everything)

	if err := db.RevokeToken(ctx, account.ID, "session"); err != nil {
		t.Fatal(err)
	}
	liveness(t, db, now, map[string]bool{"session": false, "docs": false, "admin": false, "elsewhere": true, "docs-elsewhere": true, "machine": true})

	// A child written after its parent died, as a binary that did not
	// cascade could leave, goes the next time the parent is revoked, which
	// is itself still not found.
	if err := db.InsertToken(ctx, token("late", "https://late.example", "session")); err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeToken(ctx, account.ID, "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking a dead parent: %v", err)
	}
	liveness(t, db, now, map[string]bool{"late": false, "machine": true})
}

func TestReplaceTokenReplacesOnlyItsOwnSignInsToken(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account, _ := db.SignIn(ctx, "github", "1", "one")

	token := func(id, audience, parent string) Token {
		return Token{ID: id, SecretHash: "h", AccountID: account.ID, Name: id, Audience: audience, ParentID: parent, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	for _, tk := range []Token{token("session", "", ""), token("other-session", "", ""), token("machine", "https://docs.example", "")} {
		if err := db.InsertToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	for _, tk := range []Token{
		token("first", "https://docs.example", "session"),
		token("admin", "https://admin.example", "session"),
		token("theirs", "https://docs.example", "other-session"),
		token("second", "https://docs.example", "session"),
	} {
		if err := db.ReplaceToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	liveness(t, db, now, map[string]bool{"first": false, "second": true, "admin": true, "theirs": true, "machine": true, "session": true, "other-session": true})

	// Nothing without a parent goes through here, so nothing without one
	// can be replaced.
	if err := db.ReplaceToken(ctx, token("loose", "https://docs.example", "")); err == nil {
		t.Fatal("a token with no parent was accepted")
	}
	if _, err := db.TokenByID(ctx, "loose"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the refused token was stored: %v", err)
	}
	liveness(t, db, now, map[string]bool{"machine": true})

	// Only account tokens count toward the cap.
	if count, err := db.LiveAccountTokenCount(ctx, account.ID, now); err != nil || count != 2 {
		t.Fatalf("live account tokens = %d, %v", count, err)
	}
}

// A binary from before parent_id keeps working on a database that has it:
// its statements name their columns and the column has a default. Proved
// with the old statements themselves, before and after the migration.
func TestParentMigrationKeepsTheOldStatementsWorking(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	account, err := db.SignIn(ctx, "github", "1", "one")
	if err != nil {
		t.Fatal(err)
	}
	const (
		oldInsert = `INSERT INTO tokens (id, secret_hash, account_id, name, audience, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
		oldSelect = `SELECT id, secret_hash, account_id, name, audience, created_at, expires_at, revoked_at FROM tokens WHERE id = ?`
		oldRevoke = `UPDATE tokens SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL`
	)
	stamp := func(d time.Duration) string { return time.Now().UTC().Add(d).Format(time.RFC3339Nano) }

	// Back to the schema before parent_id, with a token in it.
	for _, statement := range []string{"DROP INDEX tokens_parent", "ALTER TABLE tokens DROP COLUMN parent_id", "PRAGMA user_version = 3"} {
		if _, err := db.sql.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if _, err := db.sql.Exec(oldInsert, "before", "h", account.ID, "handoff docs.example", "https://docs.example", stamp(0), stamp(time.Hour), nil); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.sql.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatalf("user_version = %d, %v", version, err)
	}
	before, err := db.TokenByID(ctx, "before")
	if err != nil || before.ParentID != "" || !before.Live(time.Now()) {
		t.Fatalf("a token from before the migration: %+v %v", before, err)
	}

	if _, err := db.sql.Exec(oldInsert, "after", "h", account.ID, "sign-in", "", stamp(0), stamp(time.Hour), nil); err != nil {
		t.Fatalf("the old insert on the migrated schema: %v", err)
	}
	var id, hash, owner, name, audience, created string
	var expires, revoked sql.NullString
	if err := db.sql.QueryRow(oldSelect, "after").Scan(&id, &hash, &owner, &name, &audience, &created, &expires, &revoked); err != nil {
		t.Fatalf("the old select on the migrated schema: %v", err)
	}
	if res, err := db.sql.Exec(oldRevoke, stamp(0), "after", account.ID); err != nil {
		t.Fatalf("the old revoke on the migrated schema: %v", err)
	} else if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("the old revoke touched %d rows", n)
	}
	after, err := db.TokenByID(ctx, "after")
	if err != nil || after.ParentID != "" || after.Live(time.Now()) {
		t.Fatalf("a token the old binary wrote: %+v %v", after, err)
	}
}
