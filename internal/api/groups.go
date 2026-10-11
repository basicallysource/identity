package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/basicallysource/identity/internal/store"
)

// Group administration. Every route here is for members of identity-admin
// holding an account token: the secure middleware already refuses an
// application (audience-bound) token anything past whoami and avatar, so a
// consuming service's handoff credential cannot reach these even if the
// person behind it is an administrator. Administration is done here, signed
// in here, on purpose.
//
// The one exception is reading a group. A configured group reader (see
// GroupReader) may GET the groups it was given, members and their provider
// ids included, and nothing else: no other group, no list of groups, no
// write. That is for a service that acts on membership with nobody signed in,
// such as a chat bot that mirrors a group into a chat role.

// GroupReader is a service allowed to read the members of the named groups.
// It holds a static secret of its own; identity is configured with only the
// secret's SHA-256, so the configuration is not itself a credential.
type GroupReader struct {
	Name       string
	SecretHash [sha256.Size]byte
	Groups     []string
}

// ParseGroupReaders reads IDENTITY_GROUP_READERS: comma-separated entries of
// name:sha256-hex-of-the-secret:group+group. A malformed entry is an error,
// not a skipped line, so a typo cannot quietly cut a service off.
func ParseGroupReaders(value string) ([]GroupReader, error) {
	var readers []GroupReader
	for _, entry := range strings.Split(value, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, ":")
		if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
			return nil, fmt.Errorf("group reader %q: want name:sha256-hex:group+group", entry)
		}
		sum, err := hex.DecodeString(parts[1])
		if err != nil || len(sum) != sha256.Size {
			return nil, fmt.Errorf("group reader %q: the secret's hash must be 64 hex characters", parts[0])
		}
		reader := GroupReader{Name: parts[0], Groups: strings.Split(parts[2], "+")}
		copy(reader.SecretHash[:], sum)
		readers = append(readers, reader)
	}
	return readers, nil
}

// groupReader reports which configured reader, if any, the request's bearer
// secret belongs to. Every reader is compared, in constant time.
func (s *Server) groupReader(r *http.Request) (GroupReader, bool) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(s.GroupReaders) == 0 {
		return GroupReader{}, false
	}
	sum := sha256.Sum256([]byte(strings.TrimSpace(bearer)))
	var found GroupReader
	match := false
	for _, reader := range s.GroupReaders {
		if subtle.ConstantTimeCompare(sum[:], reader.SecretHash[:]) == 1 {
			found, match = reader, true
		}
	}
	return found, match
}

// requireGroupRead lets a group reader read a group it was given, and
// anybody else through requireAdmin.
func (s *Server) requireGroupRead(w http.ResponseWriter, r *http.Request, group string) bool {
	if reader, ok := s.groupReader(r); ok {
		if !slices.Contains(reader.Groups, group) {
			writeError(w, http.StatusForbidden, "this reader may not read that group")
			return false
		}
		return true
	}
	_, ok := s.requireAdmin(w, r)
	return ok
}

type groupBody struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
	Members     int       `json:"members"`
}

type memberBody struct {
	Account string    `json:"account"`
	Handle  string    `json:"handle"`
	AddedAt time.Time `json:"added_at"`
	AddedBy string    `json:"added_by"`
	// Identities are the member's provider proofs, so a reader can act on a
	// provider id (a Discord snowflake) without a second lookup.
	Identities []identityBody `json:"identities"`
}

type groupDetailBody struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	CreatedAt   time.Time    `json:"created_at"`
	CreatedBy   string       `json:"created_by"`
	Members     []memberBody `json:"members"`
}

type auditBody struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Group   string    `json:"group"`
	Account string    `json:"account,omitempty"`
	Handle  string    `json:"handle,omitempty"`
}

type accountBody struct {
	Account    string         `json:"account"`
	Handle     string         `json:"handle"`
	CreatedAt  time.Time      `json:"created_at"`
	Identities []identityBody `json:"identities"`
	Groups     []string       `json:"groups"`
}

// requireAdmin resolves the caller and refuses anybody outside identity-admin.
// It writes the refusal itself; the caller just returns on false.
func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) (store.Account, bool) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return store.Account{}, false
	}
	admin, err := s.Store.IsMember(r.Context(), store.AdminGroup, account.ID)
	if err != nil {
		s.logger().Error("groups: admin check", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return store.Account{}, false
	}
	if !admin {
		writeError(w, http.StatusForbidden, "managing groups requires membership of "+store.AdminGroup)
		return store.Account{}, false
	}
	return account, true
}

func describeGroup(g store.Group) groupBody {
	return groupBody{Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt, CreatedBy: g.CreatedBy, Members: g.Members}
}

func (s *Server) listGroups(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	groups, err := s.Store.Groups(r.Context())
	if err != nil {
		s.logger().Error("groups: list", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the groups")
		return
	}
	rows := []groupBody{}
	for _, g := range groups {
		rows = append(rows, describeGroup(g))
	}
	writeJSON(w, http.StatusOK, map[string]any{"groups": rows})
}

func (s *Server) createGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.Name == "" {
		writeError(w, http.StatusBadRequest, `send {"name": "...", "description": "..."}`)
		return
	}
	err := s.Store.CreateGroup(r.Context(), body.Name, body.Description, actor.ID)
	switch {
	case errors.Is(err, store.ErrBadGroupName):
		writeError(w, http.StatusBadRequest, "a group name is 1 to 63 lowercase letters, digits and hyphens, starting with a letter or digit")
		return
	case errors.Is(err, store.ErrExists):
		writeError(w, http.StatusConflict, "a group with that name already exists")
		return
	case err != nil:
		s.logger().Error("groups: create", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create the group")
		return
	}
	s.logger().Info("created a group", "group", body.Name, "by", actor.ID)
	g, _, err := s.Store.Group(r.Context(), body.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not read the group back")
		return
	}
	writeJSON(w, http.StatusCreated, describeGroup(g))
}

func (s *Server) getGroup(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.requireGroupRead(w, r, name) {
		return
	}
	body, err := s.groupDetail(r.Context(), name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such group")
		return
	case err != nil:
		s.logger().Error("groups: read", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the group")
		return
	}
	writeJSON(w, http.StatusOK, body)
}

// groupDetail is one group and its members, each with their provider proofs.
func (s *Server) groupDetail(ctx context.Context, name string) (groupDetailBody, error) {
	g, members, err := s.Store.Group(ctx, name)
	if err != nil {
		return groupDetailBody{}, err
	}
	body := groupDetailBody{Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt, CreatedBy: g.CreatedBy, Members: []memberBody{}}
	for _, m := range members {
		identities, err := s.Store.IdentitiesFor(ctx, m.AccountID)
		if err != nil {
			return groupDetailBody{}, err
		}
		member := memberBody{Account: m.AccountID, Handle: m.Handle, AddedAt: m.AddedAt, AddedBy: m.AddedBy, Identities: []identityBody{}}
		for _, identity := range identities {
			member.Identities = append(member.Identities, identityBody{Provider: identity.Provider, ID: identity.ProviderID, Handle: identity.Handle, ProvedAt: identity.ProvedAt})
		}
		body.Members = append(body.Members, member)
	}
	return body, nil
}

func (s *Server) deleteGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	err := s.Store.DeleteGroup(r.Context(), name, actor.ID)
	switch {
	case errors.Is(err, store.ErrReservedGroup):
		writeError(w, http.StatusForbidden, store.AdminGroup+" cannot be deleted")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such group")
	case err != nil:
		s.logger().Error("groups: delete", "error", err)
		writeError(w, http.StatusInternalServerError, "could not delete the group")
	default:
		s.logger().Info("deleted a group", "group", name, "by", actor.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) addMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	group, account := r.PathValue("name"), r.PathValue("account")
	err := s.Store.AddMember(r.Context(), group, account, actor.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such group or account")
	case err != nil:
		s.logger().Error("groups: add member", "error", err)
		writeError(w, http.StatusInternalServerError, "could not add the member")
	default:
		s.logger().Info("added a member", "group", group, "account", account, "by", actor.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	group, account := r.PathValue("name"), r.PathValue("account")
	err := s.Store.RemoveMember(r.Context(), group, account, actor.ID)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		writeError(w, http.StatusForbidden, "that would leave "+store.AdminGroup+" empty; add another administrator first")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "that account is not in that group")
	case err != nil:
		s.logger().Error("groups: remove member", "error", err)
		writeError(w, http.StatusInternalServerError, "could not remove the member")
	default:
		s.logger().Info("removed a member", "group", group, "account", account, "by", actor.ID)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) groupAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.Store.Audit(r.Context(), limit)
	if err != nil {
		s.logger().Error("groups: audit", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the audit log")
		return
	}
	rows := []auditBody{}
	for _, e := range entries {
		rows = append(rows, auditBody{ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, Group: e.Group, Account: e.AccountID, Handle: e.Handle})
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": rows})
}

// searchAccounts is how an administrator finds the account to put in a
// group: by handle, with every provider identity shown, because two people
// can share a handle and the provider id is what tells them apart.
func (s *Server) searchAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	matches, total, err := s.Store.SearchAccounts(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), offset, limit)
	if err != nil {
		s.logger().Error("accounts: search", "error", err)
		writeError(w, http.StatusInternalServerError, "could not search accounts")
		return
	}
	rows := []accountBody{}
	for _, m := range matches {
		groups, err := s.Store.GroupsFor(r.Context(), m.Account.ID)
		if err != nil {
			s.logger().Error("accounts: groups", "error", err)
			writeError(w, http.StatusInternalServerError, "could not search accounts")
			return
		}
		body := accountBody{Account: m.Account.ID, Handle: m.Account.Handle, CreatedAt: m.Account.CreatedAt, Identities: []identityBody{}, Groups: groups}
		for _, identity := range m.Identities {
			body.Identities = append(body.Identities, identityBody{Provider: identity.Provider, ID: identity.ProviderID, Handle: identity.Handle, ProvedAt: identity.ProvedAt})
		}
		rows = append(rows, body)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": rows, "total": total})
}
