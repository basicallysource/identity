package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Handoff is how a signed-in browser session becomes another service's
// credential. The service sends the browser to /authorize with its callback
// URL; the page here signs the person in (or already has them), asks for a
// one-time code bound to that callback, and sends the browser back with it;
// the service exchanges the code server-side for a fresh token of its own.
//
// This is the shape of an OAuth authorization-code flow with everything
// removed that our own services do not need: no client secrets (possession
// of an allowed callback URL is the client identity), no scopes, no consent
// screen. If third-party consumers ever appear, those come back.

// handoffCodeTTL is how long the browser has to carry a code across one
// redirect. Codes are single-use either way.
const handoffCodeTTL = 2 * time.Minute

// redirectAllowed reports whether a sign-in may be handed to this URL.
func (s *Server) redirectAllowed(uri string) bool {
	for _, prefix := range s.RedirectAllow {
		if prefix != "" && strings.HasPrefix(uri, prefix) {
			return true
		}
	}
	return false
}

// handoff mints a one-time code for the caller's own account.
func (s *Server) handoff(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	var body struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.RedirectURI == "" {
		writeError(w, http.StatusBadRequest, `send {"redirect_uri": "..."}`)
		return
	}
	if !s.redirectAllowed(body.RedirectURI) {
		writeError(w, http.StatusForbidden, "sign-ins are not handed off to that destination")
		return
	}

	code, err := newState()
	if err != nil {
		s.logger().Error("handoff: mint code", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start the handoff")
		return
	}
	s.rememberFlow("code:"+code, pendingFlow{
		accountID:   account.ID,
		redirectURI: body.RedirectURI,
	}, handoffCodeTTL)

	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

// exchange turns a one-time code into a fresh token for the service behind
// the redirect. The redirect must match the one the code was minted for, so
// a code lifted off one service cannot be spent by another.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.Code == "" {
		writeError(w, http.StatusBadRequest, `send {"code": "...", "redirect_uri": "..."}`)
		return
	}

	flow, ok := s.recall("code:" + body.Code)
	if !ok || flow.redirectURI == "" || flow.redirectURI != body.RedirectURI {
		writeError(w, http.StatusForbidden, "that code is not valid; sign in again")
		return
	}

	account, err := s.Store.AccountByID(r.Context(), flow.accountID)
	if err != nil {
		s.logger().Error("exchange: read account", "error", err)
		writeError(w, http.StatusForbidden, "that code is not valid; sign in again")
		return
	}

	minted, err := s.issue(r, account, "handoff "+redirectHost(flow.redirectURI))
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	s.logger().Info("handed off a sign-in", "account", account.ID, "to", redirectHost(flow.redirectURI))
	writeJSON(w, http.StatusCreated, minted)
}

func redirectHost(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" {
		return uri
	}
	return parsed.Host
}
