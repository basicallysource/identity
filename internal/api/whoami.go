package api

import (
	"context"
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
	Provider string      `json:"provider"`
	ID       string      `json:"id"`
	Handle   string      `json:"handle"`
	ProvedAt time.Time   `json:"proved_at"`
	Avatar   *avatarBody `json:"avatar,omitempty"`
}

type whoamiResponse struct {
	Account    string         `json:"account"`
	Handle     string         `json:"handle"`
	CreatedAt  time.Time      `json:"created_at"`
	Identities []identityBody `json:"identities"`
	// Groups is every group the account is in, sorted, and always present:
	// an account in none answers [], never null. It is the only authorization
	// claim this service makes; what a name means is the consumer's business.
	Groups              []string    `json:"groups"`
	Token               tokenBody   `json:"token"`
	Avatar              *avatarBody `json:"avatar,omitempty"`
	UploadedAvatar      *avatarBody `json:"uploaded_avatar,omitempty"`
	AvatarUploadEnabled bool        `json:"avatar_upload_enabled"`
}

type tokenBody struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Audience  string     `json:"audience"`
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
	response, err := s.describe(r.Context(), account, credential)
	if err != nil {
		s.logger().Error("whoami", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the account")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// describe is the whoami answer for an account, as seen through one
// credential. The page renders the same thing the API returns.
func (s *Server) describe(ctx context.Context, account store.Account, credential store.Token) (whoamiResponse, error) {
	identities, err := s.Store.IdentitiesFor(ctx, account.ID)
	if err != nil {
		return whoamiResponse{}, err
	}
	groups, err := s.Store.GroupsFor(ctx, account.ID)
	if err != nil {
		return whoamiResponse{}, err
	}

	selected_avatar, uploaded_avatar, provider_avatars := accountAvatars(account, identities)
	response := whoamiResponse{
		Account:             account.ID,
		Handle:              account.Handle,
		CreatedAt:           account.CreatedAt,
		Identities:          []identityBody{},
		Groups:              groups,
		Token:               describeToken(credential),
		Avatar:              selected_avatar,
		UploadedAvatar:      uploaded_avatar,
		AvatarUploadEnabled: s.Avatars != nil,
	}
	for _, identity := range identities {
		source := identity.Provider
		response.Identities = append(response.Identities, identityBody{
			Provider: identity.Provider,
			ID:       identity.ProviderID,
			Handle:   identity.Handle,
			ProvedAt: identity.ProvedAt,
			Avatar:   provider_avatars[source],
		})
	}
	return response, nil
}

// tokenRow is a token as listed: described, plus whether it is the one
// asking.
type tokenRow struct {
	tokenBody
	Current bool `json:"current,omitempty"`
}

// tokenRows lists an account's live and recently revoked tokens. Dead
// tokens stay listed briefly for audit; an expired token from months ago
// is noise.
func (s *Server) tokenRows(ctx context.Context, account store.Account, credential store.Token) ([]tokenRow, error) {
	tokens, err := s.Store.TokensFor(ctx, account.ID)
	if err != nil {
		return nil, err
	}
	rows := []tokenRow{}
	for _, t := range tokens {
		if !t.Live(s.now()) && t.RevokedAt.IsZero() {
			continue
		}
		rows = append(rows, tokenRow{tokenBody: describeToken(t), Current: t.ID == credential.ID})
	}
	return rows, nil
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}
	rows, err := s.tokenRows(r.Context(), account, credential)
	if err != nil {
		s.logger().Error("tokens: list", "error", err)
		writeError(w, http.StatusInternalServerError, "could not read the tokens")
		return
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

	minted, err := s.issue(r, account, name, "", "")
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
		Audience:  t.Audience,
		CreatedAt: t.CreatedAt,
		Revoked:   !t.RevokedAt.IsZero(),
	}
	if !t.ExpiresAt.IsZero() {
		expires := t.ExpiresAt
		body.ExpiresAt = &expires
	}
	return body
}
