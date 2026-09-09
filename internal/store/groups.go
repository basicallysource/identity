package store

// Groups are the one thing this service says about authorization: which
// accounts belong to which named set. What a group MEANS is every consuming
// service's own decision ("members of basically-core may open the admin
// page"); this service only answers "is this account in it".
//
// Groups are flat. whoami returns the list of names an account is in, and if
// nesting ever exists it will be flattened before it is answered, so no
// consumer has to know. Until then, "who is in X" and "what is A in" are each
// one indexed read with no graph to walk, which is the property that matters
// when the question is being asked during an incident.
//
// Every change is written to group_audit in the same transaction, so the
// history of who granted what cannot disagree with the grants.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// AdminGroup is the reserved group whose members may manage groups. It
// cannot be deleted, and its last member cannot be removed, so the service
// can never lock everybody out of its own administration.
const AdminGroup = "identity-admin"

var (
	// ErrBadGroupName means the name is not lowercase letters, digits and
	// hyphens, 1 to 63 characters, starting with a letter or digit.
	ErrBadGroupName = errors.New("store: invalid group name")
	// ErrExists means a group of that name already exists.
	ErrExists = errors.New("store: group exists")
	// ErrLastAdmin means the change would leave identity-admin empty.
	ErrLastAdmin = errors.New("store: cannot remove the last identity admin")
	// ErrReservedGroup means identity-admin cannot be deleted.
	ErrReservedGroup = errors.New("store: identity-admin cannot be deleted")
)

var groupNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidGroupName reports whether a name may be a group. The rule is strict on
// purpose: a group name is a string every consumer writes into its own
// configuration, and it should never need quoting or escaping anywhere.
func ValidGroupName(name string) bool { return groupNamePattern.MatchString(name) }

// Group is a named set of accounts.
type Group struct {
	Name        string
	Description string
	CreatedAt   time.Time
	CreatedBy   string
	// Members is how many accounts are in it, for listings.
	Members int
}

// Member is one account's membership in a group.
type Member struct {
	AccountID string
	Handle    string
	AddedAt   time.Time
	AddedBy   string
}

// AuditEntry is one recorded change to groups or their members. Actor is the
// account id that made it, or "cli" for the operator command.
type AuditEntry struct {
	ID        int64
	At        time.Time
	Actor     string
	Action    string
	Group     string
	AccountID string
	Handle    string
}

// The audit actions.
const (
	AuditCreateGroup  = "create-group"
	AuditDeleteGroup  = "delete-group"
	AuditAddMember    = "add-member"
	AuditRemoveMember = "remove-member"
)

const groupSchema = `
CREATE TABLE IF NOT EXISTS groups (
	name        TEXT PRIMARY KEY,
	description TEXT NOT NULL DEFAULT '',
	created_at  TEXT NOT NULL,
	created_by  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
	group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
	account_id TEXT NOT NULL REFERENCES accounts(id),
	added_at   TEXT NOT NULL,
	added_by   TEXT NOT NULL,
	PRIMARY KEY (group_name, account_id)
);
CREATE INDEX IF NOT EXISTS group_members_account ON group_members(account_id);
CREATE TABLE IF NOT EXISTS group_audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	at         TEXT NOT NULL,
	actor      TEXT NOT NULL,
	action     TEXT NOT NULL,
	group_name TEXT NOT NULL,
	account_id TEXT NOT NULL DEFAULT '',
	handle     TEXT NOT NULL DEFAULT ''
);
`

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func audit(ctx context.Context, x execer, actor, action, group, accountID, handle string) error {
	_, err := x.ExecContext(ctx,
		`INSERT INTO group_audit (at, actor, action, group_name, account_id, handle) VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339Nano), actor, action, group, accountID, handle)
	if err != nil {
		return fmt.Errorf("store: audit %s: %w", action, err)
	}
	return nil
}

// Groups lists every group with its member count, by name.
func (db *DB) Groups(ctx context.Context) ([]Group, error) {
	rows, err := db.sql.QueryContext(ctx, `
		SELECT g.name, g.description, g.created_at, g.created_by,
		       (SELECT COUNT(*) FROM group_members m WHERE m.group_name = g.name)
		FROM groups g ORDER BY g.name`)
	if err != nil {
		return nil, fmt.Errorf("store: list groups: %w", err)
	}
	defer rows.Close()
	groups := []Group{}
	for rows.Next() {
		var g Group
		var created string
		if err := rows.Scan(&g.Name, &g.Description, &created, &g.CreatedBy, &g.Members); err != nil {
			return nil, fmt.Errorf("store: read group: %w", err)
		}
		g.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// Group returns one group and its members, or ErrNotFound.
func (db *DB) Group(ctx context.Context, name string) (Group, []Member, error) {
	var g Group
	var created string
	err := db.sql.QueryRowContext(ctx,
		`SELECT name, description, created_at, created_by FROM groups WHERE name = ?`, name).
		Scan(&g.Name, &g.Description, &created, &g.CreatedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, nil, ErrNotFound
	}
	if err != nil {
		return Group{}, nil, fmt.Errorf("store: read group %s: %w", name, err)
	}
	g.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)

	rows, err := db.sql.QueryContext(ctx, `
		SELECT m.account_id, a.handle, m.added_at, m.added_by
		FROM group_members m JOIN accounts a ON a.id = m.account_id
		WHERE m.group_name = ? ORDER BY a.handle, m.account_id`, name)
	if err != nil {
		return Group{}, nil, fmt.Errorf("store: members of %s: %w", name, err)
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		var m Member
		var added string
		if err := rows.Scan(&m.AccountID, &m.Handle, &added, &m.AddedBy); err != nil {
			return Group{}, nil, fmt.Errorf("store: read member: %w", err)
		}
		m.AddedAt, _ = time.Parse(time.RFC3339Nano, added)
		members = append(members, m)
	}
	g.Members = len(members)
	return g, members, rows.Err()
}

// CreateGroup makes an empty group.
func (db *DB) CreateGroup(ctx context.Context, name, description, actor string) error {
	if !ValidGroupName(name) {
		return ErrBadGroupName
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin create group: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO groups (name, description, created_at, created_by) VALUES (?, ?, ?, ?)`,
		name, strings.TrimSpace(description), time.Now().UTC().Format(time.RFC3339Nano), actor)
	if err != nil {
		return fmt.Errorf("store: create group %s: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrExists
	}
	if err := audit(ctx, tx, actor, AuditCreateGroup, name, "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteGroup removes a group and every membership in it. identity-admin is
// refused: a service with no administrators cannot be administered.
func (db *DB) DeleteGroup(ctx context.Context, name, actor string) error {
	if name == AdminGroup {
		return ErrReservedGroup
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin delete group: %w", err)
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `DELETE FROM groups WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("store: delete group %s: %w", name, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := audit(ctx, tx, actor, AuditDeleteGroup, name, "", ""); err != nil {
		return err
	}
	return tx.Commit()
}

// AddMember puts an account in a group. Adding somebody who is already in it
// is not an error and is not audited, so a repeated click leaves no trace of
// a change that did not happen. The group and the account must both exist.
func (db *DB) AddMember(ctx context.Context, group, accountID, actor string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin add member: %w", err)
	}
	defer tx.Rollback()

	var handle string
	if err := tx.QueryRowContext(ctx, `SELECT handle FROM accounts WHERE id = ?`, accountID).Scan(&handle); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: read account %s: %w", accountID, err)
	}
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups WHERE name = ?`, group).Scan(&exists); err != nil || exists == 0 {
		return ErrNotFound
	}
	res, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO group_members (group_name, account_id, added_at, added_by) VALUES (?, ?, ?, ?)`,
		group, accountID, time.Now().UTC().Format(time.RFC3339Nano), actor)
	if err != nil {
		return fmt.Errorf("store: add %s to %s: %w", accountID, group, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	if err := audit(ctx, tx, actor, AuditAddMember, group, accountID, handle); err != nil {
		return err
	}
	return tx.Commit()
}

// RemoveMember takes an account out of a group. Removing the last member of
// identity-admin is refused.
func (db *DB) RemoveMember(ctx context.Context, group, accountID, actor string) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin remove member: %w", err)
	}
	defer tx.Rollback()

	if group == AdminGroup {
		var admins int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM group_members WHERE group_name = ?`, AdminGroup).Scan(&admins); err != nil {
			return fmt.Errorf("store: count admins: %w", err)
		}
		var member int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM group_members WHERE group_name = ? AND account_id = ?`, AdminGroup, accountID).Scan(&member); err != nil {
			return fmt.Errorf("store: check admin: %w", err)
		}
		if member == 1 && admins <= 1 {
			return ErrLastAdmin
		}
	}
	var handle string
	tx.QueryRowContext(ctx, `SELECT handle FROM accounts WHERE id = ?`, accountID).Scan(&handle)
	res, err := tx.ExecContext(ctx,
		`DELETE FROM group_members WHERE group_name = ? AND account_id = ?`, group, accountID)
	if err != nil {
		return fmt.Errorf("store: remove %s from %s: %w", accountID, group, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if err := audit(ctx, tx, actor, AuditRemoveMember, group, accountID, handle); err != nil {
		return err
	}
	return tx.Commit()
}

// GroupsFor is the names of every group an account is in, sorted. Never nil:
// an account in no groups is an empty list, which is what whoami answers.
func (db *DB) GroupsFor(ctx context.Context, accountID string) ([]string, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT group_name FROM group_members WHERE account_id = ? ORDER BY group_name`, accountID)
	if err != nil {
		return nil, fmt.Errorf("store: groups for %s: %w", accountID, err)
	}
	defer rows.Close()
	groups := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: read membership: %w", err)
		}
		groups = append(groups, name)
	}
	return groups, rows.Err()
}

// IsMember reports whether an account is in a group.
func (db *DB) IsMember(ctx context.Context, group, accountID string) (bool, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM group_members WHERE group_name = ? AND account_id = ?`, group, accountID).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store: membership of %s in %s: %w", accountID, group, err)
	}
	return n == 1, nil
}

// Audit returns the most recent changes, newest first.
func (db *DB) Audit(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT id, at, actor, action, group_name, account_id, handle FROM group_audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store: audit: %w", err)
	}
	defer rows.Close()
	entries := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Group, &e.AccountID, &e.Handle); err != nil {
			return nil, fmt.Errorf("store: read audit: %w", err)
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// AccountMatch is an account as a search result: the account and every
// provider identity that proves it, so a person can be told apart from a
// namesake by which GitHub or Discord they are.
type AccountMatch struct {
	Account    Account
	Identities []Identity
}

// SearchAccounts finds accounts whose handle, or any of whose provider
// handles, contains q. Case-insensitive, at most limit results, by handle.
// An empty q lists the newest accounts, which is how a short roster is
// browsed at all.
func (db *DB) SearchAccounts(ctx context.Context, q string, limit int) ([]AccountMatch, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	pattern := "%" + strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(q)), "%", ""), "_", "") + "%"
	rows, err := db.sql.QueryContext(ctx, `
		SELECT DISTINCT a.id FROM accounts a
		LEFT JOIN identities i ON i.account_id = a.id
		WHERE lower(a.handle) LIKE ? OR lower(i.handle) LIKE ?
		ORDER BY a.created_at DESC LIMIT ?`, pattern, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("store: search accounts: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("store: read search: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()

	matches := []AccountMatch{}
	for _, id := range ids {
		account, err := db.AccountByID(ctx, id)
		if err != nil {
			return nil, err
		}
		identities, err := db.IdentitiesFor(ctx, id)
		if err != nil {
			return nil, err
		}
		matches = append(matches, AccountMatch{Account: account, Identities: identities})
	}
	return matches, nil
}

// ResolveAccount turns what an operator typed into exactly one account: an
// account id, or a handle that exactly one account (or one of its provider
// identities) carries. Anything ambiguous is an error naming the candidates,
// never a guess.
func (db *DB) ResolveAccount(ctx context.Context, who string) (Account, error) {
	who = strings.TrimSpace(who)
	if account, err := db.AccountByID(ctx, who); err == nil {
		return account, nil
	}
	rows, err := db.sql.QueryContext(ctx, `
		SELECT DISTINCT a.id FROM accounts a
		LEFT JOIN identities i ON i.account_id = a.id
		WHERE lower(a.handle) = lower(?) OR lower(i.handle) = lower(?)`, who, who)
	if err != nil {
		return Account{}, fmt.Errorf("store: resolve %s: %w", who, err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return Account{}, err
		}
		ids = append(ids, id)
	}
	switch len(ids) {
	case 0:
		return Account{}, ErrNotFound
	case 1:
		return db.AccountByID(ctx, ids[0])
	default:
		return Account{}, fmt.Errorf("store: %q names %d accounts (%s); use the account id", who, len(ids), strings.Join(ids, ", "))
	}
}
