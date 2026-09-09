package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	g, members, err := s.Store.Group(r.Context(), r.PathValue("name"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such group")
		return
	case err != nil:
		s.logger().Error("groups: read", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the group")
		return
	}
	body := groupDetailBody{Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt, CreatedBy: g.CreatedBy, Members: []memberBody{}}
	for _, m := range members {
		body.Members = append(body.Members, memberBody{Account: m.AccountID, Handle: m.Handle, AddedAt: m.AddedAt, AddedBy: m.AddedBy})
	}
	writeJSON(w, http.StatusOK, body)
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
	matches, err := s.Store.SearchAccounts(r.Context(), strings.TrimSpace(r.URL.Query().Get("q")), limit)
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
	writeJSON(w, http.StatusOK, map[string]any{"accounts": rows})
}
