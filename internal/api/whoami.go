package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/basicallysource/identity/internal/store"
)

// whoami is the seam every other service builds on: opaque token in, who it
// is out. A consuming service's whole authenticator is one GET here.

type identityBody struct {
	Provider string    `json:"provider"`
	ID       string    `json:"id"`
	Handle   string    `json:"handle"`
	ProvedAt time.Time `json:"proved_at"`
}

type whoamiResponse struct {
	Account    string         `json:"account"`
	Handle     string         `json:"handle"`
	CreatedAt  time.Time      `json:"created_at"`
	Identities []identityBody `json:"identities"`
	Token      tokenBody      `json:"token"`
}

type tokenBody struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Revoked   bool       `json:"revoked,omitempty"`
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	identities, err := s.Store.IdentitiesFor(r.Context(), account.ID)
	if err != nil {
		s.logger().Error("whoami: identities", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return
	}

	response := whoamiResponse{
		Account:   account.ID,
		Handle:    account.Handle,
		CreatedAt: account.CreatedAt,
		Token:     describeToken(credential),
	}
	for _, identity := range identities {
		response.Identities = append(response.Identities, identityBody{
			Provider: identity.Provider,
			ID:       identity.ProviderID,
			Handle:   identity.Handle,
			ProvedAt: identity.ProvedAt,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	tokens, err := s.Store.TokensFor(r.Context(), account.ID)
	if err != nil {
		s.logger().Error("tokens: list", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the tokens")
		return
	}

	type row struct {
		tokenBody
		Current bool `json:"current,omitempty"`
	}
	rows := []row{}
	for _, t := range tokens {
		// Dead tokens stay listed briefly useful for audit, but only live
		// and recently revoked ones; an expired token from months ago is
		// noise.
		if !t.Live(s.now()) && t.RevokedAt.IsZero() {
			continue
		}
		rows = append(rows, row{tokenBody: describeToken(t), Current: t.ID == credential.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": rows})
}

func (s *Server) mintToken(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	var body struct {
		Name string `json:"name"`
	}
	if r.Body != nil {
		json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body)
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = "token"
	}

	minted, err := s.issue(r, account, name)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, minted)
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	err = s.Store.RevokeToken(r.Context(), account.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "no such live token on this account")
	case err != nil:
		s.logger().Error("tokens: revoke", "error", err)
		writeError(w, http.StatusInternalServerError, "could not revoke the token")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func describeToken(t store.Token) tokenBody {
	body := tokenBody{
		ID:        t.ID,
		Name:      t.Name,
		CreatedAt: t.CreatedAt,
		Revoked:   !t.RevokedAt.IsZero(),
	}
	if !t.ExpiresAt.IsZero() {
		expires := t.ExpiresAt
		body.ExpiresAt = &expires
	}
	return body
}
