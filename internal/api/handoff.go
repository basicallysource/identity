package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/basicallysource/identity/internal/store"
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
//
// A token handed off from the browser signed in here is linked to that
// sign-in (its parent), which is what makes one sign-in carry across every
// service and one sign-out end it everywhere: revoking the sign-in revokes
// every token minted from it. A code asked for through the API by a bearer
// token is a deliberate machine credential and stands alone.

// handoffCodeTTL is how long the browser has to carry a code across one
// redirect. Codes are single-use either way.
const handoffCodeTTL = 2 * time.Minute

// redirectAllowed reports whether a sign-in may be handed to this URL.
func (s *Server) redirectAllowed(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.Host == "" {
		return false
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")) {
		return false
	}
	for _, prefix := range s.RedirectAllow {
		allowed, err := url.Parse(prefix)
		if err != nil || allowed.User != nil || allowed.RawQuery != "" || allowed.Fragment != "" {
			continue
		}
		if parsed.Scheme != allowed.Scheme || parsed.Host != allowed.Host {
			continue
		}
		if parsed.Path == allowed.Path || (strings.HasSuffix(allowed.Path, "/") && strings.HasPrefix(parsed.Path, allowed.Path)) {
			return true
		}
	}
	return false
}

// handoff mints a one-time code for the caller's own account. The token it
// becomes has no parent: nothing but its own revocation ends it.
func (s *Server) handoff(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}

	var body struct {
		RedirectURI   string `json:"redirect_uri"`
		CodeChallenge string `json:"code_challenge"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.RedirectURI == "" {
		writeError(w, http.StatusBadRequest, `send {"redirect_uri": "..."}`)
		return
	}
	code, fail := s.mintHandoff(account, credential, "", body.RedirectURI, body.CodeChallenge)
	if fail != nil {
		fail.write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

// mintHandoff is the code-minting half of a handoff, shared by the API and
// the page: the destination must be allowed, the challenge well-formed, and
// the code remembered against the credential that asked, so revoking that
// sign-in kills the code too. parent is the sign-in the eventual token is
// linked to: the page's own session, or empty.
func (s *Server) mintHandoff(account store.Account, credential store.Token, parent, redirectURI, codeChallenge string) (string, *failure) {
	if codeChallenge != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(codeChallenge)
		if err != nil || len(decoded) != 32 {
			return "", &failure{http.StatusBadRequest, "invalid code challenge", ""}
		}
	}
	if !s.redirectAllowed(redirectURI) {
		return "", &failure{http.StatusForbidden, "sign-ins are not handed off to that destination", ""}
	}
	code, err := newState()
	if err != nil {
		s.logger().Error("handoff: mint code", "error", err)
		return "", &failure{http.StatusInternalServerError, "could not start the handoff", ""}
	}
	s.rememberFlow("code:"+code, pendingFlow{
		accountID:     account.ID,
		redirectURI:   redirectURI,
		codeChallenge: codeChallenge,
		tokenID:       credential.ID,
		parentID:      parent,
	}, handoffCodeTTL)
	return code, nil
}

// exchange turns a one-time code into a fresh token for the service behind
// the redirect. The redirect must match the one the code was minted for, so
// a code lifted off one service cannot be spent by another.
func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code         string `json:"code"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirect_uri"`
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

	if flow.codeChallenge != "" {
		sum := sha256.Sum256([]byte(body.CodeVerifier))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if len(body.CodeVerifier) < 43 || len(body.CodeVerifier) > 128 || subtle.ConstantTimeCompare([]byte(got), []byte(flow.codeChallenge)) != 1 {
			writeError(w, 403, "invalid code verifier")
			return
		}
	}
	asker, err := s.Store.TokenByID(r.Context(), flow.tokenID)
	if err != nil || !asker.Live(s.now()) {
		writeError(w, 403, "sign-in was revoked")
		return
	}
	account, err := s.Store.AccountByID(r.Context(), flow.accountID)
	if err != nil {
		s.logger().Error("exchange: read account", "error", err)
		writeError(w, http.StatusForbidden, "that code is not valid; sign in again")
		return
	}

	minted, err := s.issue(r, account, "handoff "+redirectHost(flow.redirectURI), redirectOrigin(flow.redirectURI), flow.parentID)
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	s.logger().Info("handed off a sign-in", "account", account.ID, "to", redirectHost(flow.redirectURI))
	writeJSON(w, http.StatusCreated, minted)
}

// signout is a service ending its browser's session, with the token that
// session holds. The token's parent is the browser's sign-in here; revoking
// it revokes every token minted from it, the caller's included, so the
// browser is signed out here and at every service it reached. A token with
// no parent is revoked alone, with anything minted from it.
func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "a live bearer token is required")
		return
	}
	session := credential.ID
	if credential.ParentID != "" {
		session = credential.ParentID
	}
	// A sign-in that was already revoked is not found, but its children,
	// the caller among them, are revoked all the same: still a sign-out.
	if err := s.Store.RevokeToken(r.Context(), account.ID, session); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logger().Error("signout", "error", err)
		writeError(w, http.StatusInternalServerError, "could not sign out")
		return
	}
	s.logger().Info("signed a browser out", "account", account.ID, "from", credential.Audience)
	w.WriteHeader(http.StatusNoContent)
}

// callbackRedirect is a consuming service's callback with an answer added
// to whatever query it already carries.
func callbackRedirect(redirectURI string, answer url.Values) string {
	glue := "?"
	if strings.Contains(redirectURI, "?") {
		glue = "&"
	}
	return redirectURI + glue + answer.Encode()
}

func redirectHost(uri string) string {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Host == "" {
		return uri
	}
	return parsed.Host
}

func redirectOrigin(uri string) string {
	parsed, _ := url.Parse(uri)
	return parsed.Scheme + "://" + parsed.Host
}
