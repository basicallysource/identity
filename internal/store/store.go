// Package store is the whole database: who exists, which provider identities
// prove them, and which tokens speak for them.
//
// The shape is three tables. An account is the person; it owns nothing but an
// id and a display handle. An identity is one proof of that person at a
// provider (github, discord), keyed by the provider's own immutable id, never
// by a login that can be renamed and re-registered. A token is an opaque
// credential this service minted; its secret is stored only as a hash.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is the one answer for anything that isn't there.
	ErrNotFound = errors.New("store: not found")
	// ErrLinkedElsewhere means this provider identity already proves a
	// different account. Merging accounts is a deliberate operation this
	// service does not do yet, so the link is refused rather than guessed at.
	ErrLinkedElsewhere = errors.New("store: identity belongs to another account")
)

// Account is the person behind every identity and token.
type Account struct {
	ID        string
	Handle    string
	CreatedAt time.Time
}

// Identity is one provider's proof of an account. ProviderID is the
// provider's immutable id (GitHub's numeric id, Discord's snowflake), and
// Handle is the human-readable name at the time of the last proof.
type Identity struct {
	Provider   string
	ProviderID string
	AccountID  string
	Handle     string
	ProvedAt   time.Time
}

// Token is a credential as the store holds it: id in the clear, secret only
// as a hash. ExpiresAt zero means it does not expire; RevokedAt zero means it
// has not been revoked.
type Token struct {
	ID         string
	SecretHash string
	AccountID  string
	Name       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
}

// Live reports whether the token still works at a moment.
func (t Token) Live(now time.Time) bool {
	if !t.RevokedAt.IsZero() {
		return false
	}
	return t.ExpiresAt.IsZero() || t.ExpiresAt.After(now)
}

// DB is the open database.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One writer at a time is this service's whole load; WAL keeps readers
	// out of the writer's way and busy_timeout absorbs the rest.
	for _, pragma := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create schema: %w", err)
	}
	return &DB{sql: db}, nil
}

// Close closes the database.
func (db *DB) Close() error { return db.sql.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS accounts (
	id         TEXT PRIMARY KEY,
	handle     TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identities (
	provider    TEXT NOT NULL,
	provider_id TEXT NOT NULL,
	account_id  TEXT NOT NULL REFERENCES accounts(id),
	handle      TEXT NOT NULL,
	proved_at   TEXT NOT NULL,
	PRIMARY KEY (provider, provider_id)
);
CREATE INDEX IF NOT EXISTS identities_account ON identities(account_id);
CREATE TABLE IF NOT EXISTS tokens (
	id          TEXT PRIMARY KEY,
	secret_hash TEXT NOT NULL,
	account_id  TEXT NOT NULL REFERENCES accounts(id),
	name        TEXT NOT NULL,
	created_at  TEXT NOT NULL,
	expires_at  TEXT,
	revoked_at  TEXT
);
CREATE INDEX IF NOT EXISTS tokens_account ON tokens(account_id);
`

// SignIn records a successful proof at a provider and returns the account it
// proves. An unknown identity creates a fresh account; a known one refreshes
// its handle. Either way the provider's answer is the truth about the handle.
func (db *DB) SignIn(ctx context.Context, provider, providerID, handle string) (Account, error) {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return Account{}, fmt.Errorf("store: begin sign-in: %w", err)
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)

	var accountID string
	err = tx.QueryRowContext(ctx,
		`SELECT account_id FROM identities WHERE provider = ? AND provider_id = ?`,
		provider, providerID).Scan(&accountID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		accountID, err = newID()
		if err != nil {
			return Account{}, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO accounts (id, handle, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			accountID, handle, stamp, stamp); err != nil {
			return Account{}, fmt.Errorf("store: create account: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO identities (provider, provider_id, account_id, handle, proved_at)
			 VALUES (?, ?, ?, ?, ?)`,
			provider, providerID, accountID, handle, stamp); err != nil {
			return Account{}, fmt.Errorf("store: create identity: %w", err)
		}
	case err != nil:
		return Account{}, fmt.Errorf("store: find identity: %w", err)
	default:
		if _, err := tx.ExecContext(ctx,
			`UPDATE identities SET handle = ?, proved_at = ? WHERE provider = ? AND provider_id = ?`,
			handle, stamp, provider, providerID); err != nil {
			return Account{}, fmt.Errorf("store: refresh identity: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE accounts SET updated_at = ? WHERE id = ?`, stamp, accountID); err != nil {
			return Account{}, fmt.Errorf("store: touch account: %w", err)
		}
	}

	account, err := accountByID(ctx, tx, accountID)
	if err != nil {
		return Account{}, err
	}
	if err := tx.Commit(); err != nil {
		return Account{}, fmt.Errorf("store: commit sign-in: %w", err)
	}
	return account, nil
}

// Link attaches a provider identity to an existing account. An identity
// already proving another account is refused, never moved.
func (db *DB) Link(ctx context.Context, accountID, provider, providerID, handle string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin link: %w", err)
	}
	defer tx.Rollback()

	stamp := time.Now().UTC().Format(time.RFC3339Nano)

	var owner string
	err = tx.QueryRowContext(ctx,
		`SELECT account_id FROM identities WHERE provider = ? AND provider_id = ?`,
		provider, providerID).Scan(&owner)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO identities (provider, provider_id, account_id, handle, proved_at)
			 VALUES (?, ?, ?, ?, ?)`,
			provider, providerID, accountID, handle, stamp); err != nil {
			return fmt.Errorf("store: link identity: %w", err)
		}
	case err != nil:
		return fmt.Errorf("store: find identity: %w", err)
	case owner != accountID:
		return ErrLinkedElsewhere
	default:
		if _, err := tx.ExecContext(ctx,
			`UPDATE identities SET handle = ?, proved_at = ? WHERE provider = ? AND provider_id = ?`,
			handle, stamp, provider, providerID); err != nil {
			return fmt.Errorf("store: refresh identity: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit link: %w", err)
	}
	return nil
}

// AccountByID returns one account, or ErrNotFound.
func (db *DB) AccountByID(ctx context.Context, id string) (Account, error) {
	return accountByID(ctx, db.sql, id)
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func accountByID(ctx context.Context, q querier, id string) (Account, error) {
	var a Account
	var created string
	err := q.QueryRowContext(ctx,
		`SELECT id, handle, created_at FROM accounts WHERE id = ?`, id).
		Scan(&a.ID, &a.Handle, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("store: read account: %w", err)
	}
	a.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	return a, nil
}

// IdentitiesFor lists an account's proofs, oldest first.
func (db *DB) IdentitiesFor(ctx context.Context, accountID string) ([]Identity, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT provider, provider_id, account_id, handle, proved_at FROM identities
		 WHERE account_id = ? ORDER BY proved_at ASC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: identities for %s: %w", accountID, err)
	}
	defer rows.Close()

	var identities []Identity
	for rows.Next() {
		var i Identity
		var proved string
		if err := rows.Scan(&i.Provider, &i.ProviderID, &i.AccountID, &i.Handle, &proved); err != nil {
			return nil, fmt.Errorf("store: read identity: %w", err)
		}
		i.ProvedAt, _ = time.Parse(time.RFC3339Nano, proved)
		identities = append(identities, i)
	}
	return identities, rows.Err()
}

// InsertToken records a freshly minted token.
func (db *DB) InsertToken(ctx context.Context, t Token) error {
	var expires, revoked any
	if !t.ExpiresAt.IsZero() {
		expires = t.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	if !t.RevokedAt.IsZero() {
		revoked = t.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO tokens (id, secret_hash, account_id, name, created_at, expires_at, revoked_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.SecretHash, t.AccountID, t.Name,
		t.CreatedAt.UTC().Format(time.RFC3339Nano), expires, revoked)
	if err != nil {
		return fmt.Errorf("store: insert token %s: %w", t.ID, err)
	}
	return nil
}

// TokenByID returns one token, or ErrNotFound.
func (db *DB) TokenByID(ctx context.Context, id string) (Token, error) {
	row := db.sql.QueryRowContext(ctx,
		`SELECT id, secret_hash, account_id, name, created_at, expires_at, revoked_at
		 FROM tokens WHERE id = ?`, id)
	return scanToken(row.Scan)
}

// TokensFor lists an account's tokens, newest first.
func (db *DB) TokensFor(ctx context.Context, accountID string) ([]Token, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, secret_hash, account_id, name, created_at, expires_at, revoked_at
		 FROM tokens WHERE account_id = ? ORDER BY created_at DESC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: tokens for %s: %w", accountID, err)
	}
	defer rows.Close()

	var tokens []Token
	for rows.Next() {
		t, err := scanToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// LiveTokenCount counts an account's usable tokens, so "make another one"
// cannot go on forever.
func (db *DB) LiveTokenCount(ctx context.Context, accountID string, now time.Time) (int, error) {
	var count int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tokens
		 WHERE account_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`,
		accountID, now.UTC().Format(time.RFC3339Nano)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("store: live tokens for %s: %w", accountID, err)
	}
	return count, nil
}

// RevokeToken makes one of an account's tokens stop working. The account id
// is part of the key so nobody can revoke somebody else's token by id alone.
func (db *DB) RevokeToken(ctx context.Context, accountID, tokenID string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE tokens SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), tokenID, accountID)
	if err != nil {
		return fmt.Errorf("store: revoke token %s: %w", tokenID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func scanToken(scan func(...any) error) (Token, error) {
	var t Token
	var created string
	var expires, revoked sql.NullString
	err := scan(&t.ID, &t.SecretHash, &t.AccountID, &t.Name, &created, &expires, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("store: read token: %w", err)
	}
	t.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if expires.Valid {
		t.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expires.String)
	}
	if revoked.Valid {
		t.RevokedAt, _ = time.Parse(time.RFC3339Nano, revoked.String)
	}
	return t, nil
}

// newID mints an account id: 12 hex characters of randomness, plenty for a
// service whose account count is measured in humans.
func newID() (string, error) {
	raw := make([]byte, 6)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("store: mint id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
