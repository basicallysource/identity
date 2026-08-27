package store

import (
	"context"
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

	count, err := db.LiveTokenCount(ctx, account.ID, now)
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
