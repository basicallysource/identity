package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
	"github.com/basicallysource/identity/internal/token"
)

// Signing in is how somebody gets an account and a token without anyone here
// doing anything: they prove they are a GitHub or Discord account, and that
// proof either names an existing account or creates one.
//
// Every flow doubles as a link: the same start endpoint called WITH a bearer
// token attaches the proved identity to the caller's account instead of
// signing in, which is how one account comes to hold both providers.

const signInBodyLimit = 4 << 10

type tokenResponse struct {
	Token     string     `json:"token"`
	Account   string     `json:"account"`
	Handle    string     `json:"handle"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// githubStart asks GitHub for a device code for the caller to approve.
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	if !s.GitHub.Configured() {
		writeError(w, http.StatusNotImplemented, "GitHub sign-in is not configured on this service")
		return
	}
	if !s.throttle.allow(clientAddr(r), s.now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a minute")
		return
	}

	// A bearer token turns this flow into a link to that account.
	linkTo := ""
	if account, _, err := s.authenticate(r); err == nil {
		linkTo = account.ID
	} else if !errors.Is(err, errNoCredentials) {
		writeError(w, http.StatusUnauthorized, "that token no longer works; sign in again")
		return
	}

	device, err := s.GitHub.Start(r.Context())
	if err != nil {
		s.logger().Error("sign-in: github start", "error", err)
		writeError(w, http.StatusBadGateway, "could not reach GitHub")
		return
	}
	if linkTo != "" {
		s.remember("device:"+device.DeviceCode, linkTo)
	}

	writeJSON(w, http.StatusOK, device)
}

// githubFinish turns an approved device code into a token, or a link.
func (s *Server) githubFinish(w http.ResponseWriter, r *http.Request) {
	if !s.GitHub.Configured() {
		writeError(w, http.StatusNotImplemented, "GitHub sign-in is not configured on this service")
		return
	}

	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.DeviceCode == "" {
		writeError(w, http.StatusBadRequest, `send {"device_code": "..."}`)
		return
	}

	user, err := s.GitHub.Redeem(r.Context(), body.DeviceCode)
	switch {
	case errors.Is(err, provider.ErrPending):
		// Not an error: the person has not finished at github.com yet.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
		return
	case errors.Is(err, provider.ErrSlowDown):
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "slow_down"})
		return
	case errors.Is(err, provider.ErrExpired):
		writeError(w, http.StatusBadRequest, "that code expired; start again")
		return
	case errors.Is(err, provider.ErrDenied):
		writeError(w, http.StatusForbidden, "the request was declined at GitHub")
		return
	case err != nil:
		s.logger().Error("sign-in: github redeem", "error", err)
		writeError(w, http.StatusBadGateway, "could not reach GitHub")
		return
	}

	if flow, ok := s.recall("device:" + body.DeviceCode); ok && flow.accountID != "" {
		s.finishLink(w, r, flow.accountID, provider.NameGitHub, user)
		return
	}

	s.finishSignIn(w, r, provider.NameGitHub, user)
}

// discordStart mints the state for a redirect to Discord and answers with
// where to send the browser.
func (s *Server) discordStart(w http.ResponseWriter, r *http.Request) {
	if !s.Discord.Configured() {
		writeError(w, http.StatusNotImplemented, "Discord sign-in is not configured on this service")
		return
	}
	if !s.throttle.allow(clientAddr(r), s.now()) {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "too many sign-in attempts; wait a minute")
		return
	}

	linkTo := ""
	if account, _, err := s.authenticate(r); err == nil {
		linkTo = account.ID
	} else if !errors.Is(err, errNoCredentials) {
		writeError(w, http.StatusUnauthorized, "that token no longer works; sign in again")
		return
	}

	state, err := newState()
	if err != nil {
		s.logger().Error("sign-in: discord state", "error", err)
		writeError(w, http.StatusInternalServerError, "could not start sign-in")
		return
	}
	s.remember("state:"+state, linkTo)

	// The cookie ties the callback to the browser that started the flow;
	// the server-side entry ties it to this service. Both must agree.
	http.SetCookie(w, &http.Cookie{
		Name:     "identity_state",
		Value:    state,
		Path:     "/signin/discord",
		MaxAge:   int(pendingFlowTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(s.BaseURL, "https://"),
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"url": s.Discord.Authorize(state, s.discordRedirect()),
	})
}

// discordCallback is where Discord sends the browser back.
func (s *Server) discordCallback(w http.ResponseWriter, r *http.Request) {
	if denied := r.URL.Query().Get("error"); denied != "" {
		s.callbackPage(w, callbackView{Error: "the request was declined at Discord"})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	cookie, err := r.Cookie("identity_state")
	if state == "" || code == "" || err != nil || cookie.Value != state {
		s.callbackPage(w, callbackView{Error: "this sign-in did not start here; start again"})
		return
	}
	flow, ok := s.recall("state:" + state)
	if !ok {
		s.callbackPage(w, callbackView{Error: "this sign-in expired; start again"})
		return
	}

	user, err := s.Discord.Redeem(r.Context(), code, s.discordRedirect())
	if err != nil {
		s.logger().Error("sign-in: discord redeem", "error", err)
		s.callbackPage(w, callbackView{Error: "could not confirm the sign-in with Discord"})
		return
	}

	if flow.accountID != "" {
		err := s.Store.Link(r.Context(), flow.accountID, provider.NameDiscord, user.ID, user.Handle)
		switch {
		case errors.Is(err, store.ErrLinkedElsewhere):
			s.callbackPage(w, callbackView{Error: "that Discord account already belongs to a different account here"})
		case err != nil:
			s.logger().Error("sign-in: discord link", "error", err)
			s.callbackPage(w, callbackView{Error: "could not record the link"})
		default:
			s.logger().Info("linked an identity", "account", flow.accountID, "provider", provider.NameDiscord, "handle", user.Handle)
			s.callbackPage(w, callbackView{Linked: true})
		}
		return
	}

	account, err := s.Store.SignIn(r.Context(), provider.NameDiscord, user.ID, user.Handle)
	if err != nil {
		s.logger().Error("sign-in: discord record", "error", err)
		s.callbackPage(w, callbackView{Error: "could not record the sign-in"})
		return
	}
	minted, err := s.issue(r, account, "")
	if err != nil {
		s.callbackPage(w, callbackView{Error: "could not issue a token: " + err.Error()})
		return
	}
	s.callbackPage(w, callbackView{Token: minted.Token})
}

func (s *Server) discordRedirect() string {
	return strings.TrimSuffix(s.BaseURL, "/") + "/signin/discord/callback"
}

// finishSignIn records the proof and answers with a fresh token.
func (s *Server) finishSignIn(w http.ResponseWriter, r *http.Request, providerName string, user provider.User) {
	account, err := s.Store.SignIn(r.Context(), providerName, user.ID, user.Handle)
	if err != nil {
		s.logger().Error("sign-in: record", "provider", providerName, "error", err)
		writeError(w, http.StatusInternalServerError, "could not record the sign-in")
		return
	}
	minted, err := s.issue(r, account, "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, minted)
}

// finishLink attaches the proof to an existing account instead.
func (s *Server) finishLink(w http.ResponseWriter, r *http.Request, accountID, providerName string, user provider.User) {
	err := s.Store.Link(r.Context(), accountID, providerName, user.ID, user.Handle)
	switch {
	case errors.Is(err, store.ErrLinkedElsewhere):
		writeError(w, http.StatusConflict, "that "+providerName+" account already belongs to a different account here")
	case err != nil:
		s.logger().Error("sign-in: link", "provider", providerName, "error", err)
		writeError(w, http.StatusInternalServerError, "could not record the link")
	default:
		s.logger().Info("linked an identity", "account", accountID, "provider", providerName, "handle", user.Handle)
		writeJSON(w, http.StatusOK, map[string]any{
			"linked":   true,
			"provider": providerName,
			"handle":   user.Handle,
		})
	}
}

// issue mints a token for an account, within policy. An empty name gets the
// sign-in default.
func (s *Server) issue(r *http.Request, account store.Account, name string) (tokenResponse, error) {
	now := s.now()
	if name == "" {
		name = "sign-in " + now.Format("2006-01-02")
	}

	live, err := s.Store.LiveTokenCount(r.Context(), account.ID, now)
	if err != nil {
		s.logger().Error("sign-in: count tokens", "error", err)
		return tokenResponse{}, errors.New("could not issue a token")
	}
	if live >= maxLiveTokens {
		return tokenResponse{}, errors.New("this account has too many live tokens; revoke some first")
	}

	minted, id, secretHash, err := token.New()
	if err != nil {
		s.logger().Error("sign-in: mint", "error", err)
		return tokenResponse{}, errors.New("could not issue a token")
	}
	expires := now.Add(tokenLifetime)

	if err := s.Store.InsertToken(r.Context(), store.Token{
		ID:         id,
		SecretHash: secretHash,
		AccountID:  account.ID,
		Name:       name,
		CreatedAt:  now,
		ExpiresAt:  expires,
	}); err != nil {
		s.logger().Error("sign-in: store token", "error", err)
		return tokenResponse{}, errors.New("could not issue a token")
	}

	s.logger().Info("issued a token", "account", account.ID, "handle", account.Handle)
	return tokenResponse{
		Token:     minted,
		Account:   account.ID,
		Handle:    account.Handle,
		ExpiresAt: &expires,
	}, nil
}
