package store

import (
	"context"
	"errors"
	"testing"
)

func TestGroupsLifecycle(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	alice, _ := db.SignIn(ctx, "github", "1", "alice")
	bob, _ := db.SignIn(ctx, "discord", "2", "bob")

	if err := db.CreateGroup(ctx, "Bad Name", "", "cli"); !errors.Is(err, ErrBadGroupName) {
		t.Fatalf("a bad name was accepted: %v", err)
	}
	if err := db.CreateGroup(ctx, "core", "the company", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateGroup(ctx, "core", "", "cli"); !errors.Is(err, ErrExists) {
		t.Fatalf("a duplicate was accepted: %v", err)
	}

	// Membership: add twice is once, and the audit says so.
	for range 2 {
		if err := db.AddMember(ctx, "core", alice.ID, "cli"); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.AddMember(ctx, "core", "nobody", "cli"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown account was added: %v", err)
	}
	if err := db.AddMember(ctx, "missing", alice.ID, "cli"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown group took a member: %v", err)
	}
	groups, err := db.GroupsFor(ctx, alice.ID)
	if err != nil || len(groups) != 1 || groups[0] != "core" {
		t.Fatalf("alice's groups = %v, %v", groups, err)
	}
	if groups, _ := db.GroupsFor(ctx, bob.ID); groups == nil || len(groups) != 0 {
		t.Fatalf("bob's groups should be an empty list, got %#v", groups)
	}
	g, members, err := db.Group(ctx, "core")
	if err != nil || g.Members != 1 || members[0].Handle != "alice" || members[0].AddedBy != "cli" {
		t.Fatalf("group = %+v members = %+v err = %v", g, members, err)
	}

	if err := db.RemoveMember(ctx, "core", alice.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveMember(ctx, "core", alice.ID, "cli"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing a non-member: %v", err)
	}

	entries, err := db.Audit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	// Newest first; the second add is not there.
	want := []string{AuditRemoveMember, AuditAddMember, AuditCreateGroup}
	if len(actions) != len(want) {
		t.Fatalf("audit = %v, want %v", actions, want)
	}
	for i := range want {
		if actions[i] != want[i] {
			t.Fatalf("audit = %v, want %v", actions, want)
		}
	}

	if err := db.DeleteGroup(ctx, "core", "cli"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.Group(ctx, "core"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted group still there: %v", err)
	}
}

func TestAdminGroupCannotBeEmptiedOrDeleted(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	alice, _ := db.SignIn(ctx, "github", "1", "alice")
	bob, _ := db.SignIn(ctx, "github", "2", "bob")

	if err := db.CreateGroup(ctx, AdminGroup, "", "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.AddMember(ctx, AdminGroup, alice.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveMember(ctx, AdminGroup, alice.ID, "cli"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("the last admin was removed: %v", err)
	}
	if err := db.DeleteGroup(ctx, AdminGroup, "cli"); !errors.Is(err, ErrReservedGroup) {
		t.Fatalf("the admin group was deleted: %v", err)
	}
	// With a second admin, the first may leave.
	if err := db.AddMember(ctx, AdminGroup, bob.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveMember(ctx, AdminGroup, alice.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if err := db.RemoveMember(ctx, AdminGroup, bob.ID, "cli"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("the last admin was removed: %v", err)
	}
}

func TestResolveAndSearchAccounts(t *testing.T) {
	db := open(t)
	ctx := context.Background()
	gh, _ := db.SignIn(ctx, "github", "1", "octocat")
	dc, _ := db.SignIn(ctx, "discord", "2", "octocat")
	other, _ := db.SignIn(ctx, "github", "3", "someone-else")

	// An id resolves; a unique handle resolves; a shared handle refuses.
	if a, err := db.ResolveAccount(ctx, other.ID); err != nil || a.ID != other.ID {
		t.Fatalf("by id: %+v %v", a, err)
	}
	if a, err := db.ResolveAccount(ctx, "Someone-Else"); err != nil || a.ID != other.ID {
		t.Fatalf("by handle: %+v %v", a, err)
	}
	if _, err := db.ResolveAccount(ctx, "octocat"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("an ambiguous handle resolved: %v", err)
	}
	if _, err := db.ResolveAccount(ctx, "nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an unknown handle: %v", err)
	}

	matches, total, err := db.SearchAccounts(ctx, "octo", 0, 10)
	if err != nil || len(matches) != 2 || total != 2 {
		t.Fatalf("search = %d matches of %d, %v", len(matches), total, err)
	}
	ids := map[string]bool{matches[0].Account.ID: true, matches[1].Account.ID: true}
	if !ids[gh.ID] || !ids[dc.ID] {
		t.Fatalf("search found %v", ids)
	}
	if all, total, _ := db.SearchAccounts(ctx, "", 0, 10); len(all) != 3 || total != 3 {
		t.Fatalf("empty search lists %d of %d, want 3", len(all), total)
	}

	// Pages: newest first, the total is the whole match, and an offset past
	// the end is an empty page rather than an error.
	first, total, _ := db.SearchAccounts(ctx, "", 0, 2)
	second, _, _ := db.SearchAccounts(ctx, "", 2, 2)
	if total != 3 || len(first) != 2 || len(second) != 1 || first[0].Account.ID != other.ID {
		t.Fatalf("pages: first %d second %d total %d, first is %s", len(first), len(second), total, first[0].Account.Handle)
	}
	if past, _, _ := db.SearchAccounts(ctx, "", 30, 2); len(past) != 0 {
		t.Fatalf("a page past the end has %d rows", len(past))
	}
}
