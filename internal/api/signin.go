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

// stateCookie ties a Discord callback to the browser that started the flow.
const stateCookie = "identity_state"

type tokenResponse struct {
	Token     string     `json:"token"`
	Account   string     `json:"account"`
	Handle    string     `json:"handle"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// failure is a refusal a flow can answer with, whichever surface asked: the
// JSON API writes it as an error body, the page renders it as a message.
type failure struct {
	status     int
	message    string
	retryAfter string
}

func (f *failure) write(w http.ResponseWriter) {
	if f.retryAfter != "" {
		w.Header().Set("Retry-After", f.retryAfter)
	}
	writeError(w, f.status, f.message)
}

// linkTarget reads whether a flow is a sign-in or, because the caller is
// already signed in, a link to that account.
func (s *Server) linkTarget(r *http.Request) (string, *failure) {
	account, _, err := s.authenticate(r)
	switch {
	case err == nil:
		return account.ID, nil
	case errors.Is(err, errNoCredentials):
		return "", nil
	default:
		return "", &failure{http.StatusUnauthorized, "that token no longer works; sign in again", ""}
	}
}

// beginGitHub asks GitHub for a device code for the caller to approve. With
// a signed-in caller the eventual proof links rather than signs in.
func (s *Server) beginGitHub(r *http.Request) (provider.Device, *failure) {
	if !s.GitHub.Configured() {
		return provider.Device{}, &failure{http.StatusNotImplemented, "GitHub sign-in is not configured on this service", ""}
	}
	if !s.throttle.allow(s.clientAddr(r), s.now()) {
		return provider.Device{}, &failure{http.StatusTooManyRequests, "too many sign-in attempts; wait a minute", "60"}
	}
	linkTo, fail := s.linkTarget(r)
	if fail != nil {
		return provider.Device{}, fail
	}
	device, err := s.GitHub.Start(r.Context())
	if err != nil {
		s.logger().Error("sign-in: github start", "error", err)
		return provider.Device{}, &failure{http.StatusBadGateway, "could not reach GitHub", ""}
	}
	if linkTo != "" {
		s.remember("device:"+device.DeviceCode, linkTo)
	}
	return device, nil
}

// redeemGitHub polls GitHub for an approved device code. pending is true
// while the person has not finished at github.com; slow is GitHub asking
// for a longer interval. On success the proved user is returned along with
// the account it links to, or "" for a sign-in.
func (s *Server) redeemGitHub(r *http.Request, deviceCode string) (user provider.User, linkTo string, pending, slow bool, fail *failure) {
	if !s.GitHub.Configured() {
		return user, "", false, false, &failure{http.StatusNotImplemented, "GitHub sign-in is not configured on this service", ""}
	}
	user, err := s.GitHub.Redeem(r.Context(), deviceCode)
	switch {
	case errors.Is(err, provider.ErrPending):
		return user, "", true, false, nil
	case errors.Is(err, provider.ErrSlowDown):
		return user, "", true, true, nil
	case errors.Is(err, provider.ErrExpired):
		return user, "", false, false, &failure{http.StatusBadRequest, "that code expired; start again", ""}
	case errors.Is(err, provider.ErrDenied):
		return user, "", false, false, &failure{http.StatusForbidden, "the request was declined at GitHub", ""}
	case err != nil:
		s.logger().Error("sign-in: github redeem", "error", err)
		return user, "", false, false, &failure{http.StatusBadGateway, "could not reach GitHub", ""}
	}
	if flow, ok := s.recall("device:" + deviceCode); ok && flow.accountID != "" {
		linkTo = flow.accountID
	}
	return user, linkTo, false, false, nil
}

// beginDiscord mints the state for a redirect to Discord, sets the cookie
// the callback must match, and answers with where to send the browser.
func (s *Server) beginDiscord(w http.ResponseWriter, r *http.Request) (string, *failure) {
	if !s.Discord.Configured() {
		return "", &failure{http.StatusNotImplemented, "Discord sign-in is not configured on this service", ""}
	}
	if !s.throttle.allow(s.clientAddr(r), s.now()) {
		return "", &failure{http.StatusTooManyRequests, "too many sign-in attempts; wait a minute", "60"}
	}
	linkTo, fail := s.linkTarget(r)
	if fail != nil {
		return "", fail
	}
	state, err := newState()
	if err != nil {
		s.logger().Error("sign-in: discord state", "error", err)
		return "", &failure{http.StatusInternalServerError, "could not start sign-in", ""}
	}
	s.remember("state:"+state, linkTo)

	// The cookie ties the callback to the browser that started the flow;
	// the server-side entry ties it to this service. Both must agree. Its
	// path is / because the __Host- prefix allows no other.
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(stateCookie),
		Value:    state,
		Path:     "/",
		MaxAge:   int(pendingFlowTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.https(),
	})
	return s.Discord.Authorize(state, s.discordRedirect()), nil
}

// githubStart is the JSON face of beginGitHub.
func (s *Server) githubStart(w http.ResponseWriter, r *http.Request) {
	device, fail := s.beginGitHub(r)
	if fail != nil {
		fail.write(w)
		return
	}
	writeJSON(w, http.StatusOK, device)
}

// githubFinish turns an approved device code into a token, or a link.
func (s *Server) githubFinish(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, signInBodyLimit)).Decode(&body); err != nil || body.DeviceCode == "" {
		writeError(w, http.StatusBadRequest, `send {"device_code": "..."}`)
		return
	}
	user, linkTo, pending, slow, fail := s.redeemGitHub(r, body.DeviceCode)
	switch {
	case fail != nil:
		fail.write(w)
	case slow:
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "slow_down"})
	case pending:
		// Not an error: the person has not finished at github.com yet.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "pending"})
	case linkTo != "":
		s.finishLink(w, r, linkTo, provider.NameGitHub, user)
	default:
		s.finishSignIn(w, r, provider.NameGitHub, user)
	}
}

// discordStart is the JSON face of beginDiscord.
func (s *Server) discordStart(w http.ResponseWriter, r *http.Request) {
	url, fail := s.beginDiscord(w, r)
	if fail != nil {
		fail.write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": url})
}

// discordCallback is where Discord sends the browser back.
func (s *Server) discordCallback(w http.ResponseWriter, r *http.Request) {
	if denied := r.URL.Query().Get("error"); denied != "" {
		s.callbackPage(w, callbackView{Error: "the request was declined at Discord"})
		return
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	cookie, err := r.Cookie(s.cookieName(stateCookie))
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
		if fail := s.completeLink(r, flow.accountID, provider.NameDiscord, user); fail != nil {
			s.callbackPage(w, callbackView{Error: fail.message})
			return
		}
		s.callbackPage(w, callbackView{Linked: true})
		return
	}

	account, fail := s.completeSignIn(r, provider.NameDiscord, user)
	if fail != nil {
		s.callbackPage(w, callbackView{Error: fail.message})
		return
	}
	minted, err := s.issue(r, account, "", "", "")
	if err != nil {
		s.callbackPage(w, callbackView{Error: "could not issue a token: " + err.Error()})
		return
	}
	s.setSession(w, minted.Token, *minted.ExpiresAt)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) discordRedirect() string {
	return strings.TrimSuffix(s.BaseURL, "/") + "/signin/discord/callback"
}

// completeSignIn records a proof as a sign-in and returns the account it
// proves, creating one on first sight.
func (s *Server) completeSignIn(r *http.Request, providerName string, user provider.User) (store.Account, *failure) {
	account, err := s.Store.SignIn(r.Context(), providerName, user.ID, user.Handle)
	if err != nil {
		s.logger().Error("sign-in: record", "provider", providerName, "error", err)
		return store.Account{}, &failure{http.StatusInternalServerError, "could not record the sign-in", ""}
	}
	s.saveProviderAvatar(r.Context(), providerName, user)
	return account, nil
}

// completeLink records a proof as a link to an existing account.
func (s *Server) completeLink(r *http.Request, accountID, providerName string, user provider.User) *failure {
	err := s.Store.Link(r.Context(), accountID, providerName, user.ID, user.Handle)
	switch {
	case errors.Is(err, store.ErrLinkedElsewhere):
		return &failure{http.StatusConflict, "that " + providerName + " account already belongs to a different account here", ""}
	case err != nil:
		s.logger().Error("sign-in: link", "provider", providerName, "error", err)
		return &failure{http.StatusInternalServerError, "could not record the link", ""}
	}
	s.saveProviderAvatar(r.Context(), providerName, user)
	s.logger().Info("linked an identity", "account", accountID, "provider", providerName, "handle", user.Handle)
	return nil
}

// finishSignIn records the proof and answers with a fresh token.
func (s *Server) finishSignIn(w http.ResponseWriter, r *http.Request, providerName string, user provider.User) {
	account, fail := s.completeSignIn(r, providerName, user)
	if fail != nil {
		fail.write(w)
		return
	}
	minted, err := s.issue(r, account, "", "", "")
	if err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	if r.Header.Get("X-Identity-Browser") == "1" {
		s.setSession(w, minted.Token, *minted.ExpiresAt)
		minted.Token = ""
	}
	writeJSON(w, http.StatusCreated, minted)
}

// finishLink attaches the proof to an existing account instead.
func (s *Server) finishLink(w http.ResponseWriter, r *http.Request, accountID, providerName string, user provider.User) {
	if fail := s.completeLink(r, accountID, providerName, user); fail != nil {
		fail.write(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"linked":   true,
		"provider": providerName,
		"handle":   user.Handle,
	})
}

// issue mints a token for an account, within policy. An empty name gets the
// sign-in default. An account token (no audience) counts against the cap. An
// application token with a parent, the browser sign-in it was minted from,
// replaces the token that sign-in last got for the same audience, which is
// what bounds those instead.
func (s *Server) issue(r *http.Request, account store.Account, name, audience, parent string) (tokenResponse, error) {
	now := s.now()
	if name == "" {
		name = "sign-in " + now.Format("2006-01-02")
	}

	if audience == "" {
		live, err := s.Store.LiveAccountTokenCount(r.Context(), account.ID, now)
		if err != nil {
			s.logger().Error("sign-in: count tokens", "error", err)
			return tokenResponse{}, errors.New("could not issue a token")
		}
		if live >= maxLiveTokens {
			return tokenResponse{}, errors.New("this account has too many live tokens; revoke some first")
		}
	}

	minted, id, secretHash, err := token.New()
	if err != nil {
		s.logger().Error("sign-in: mint", "error", err)
		return tokenResponse{}, errors.New("could not issue a token")
	}
	expires := now.Add(tokenLifetime)

	insert := s.Store.InsertToken
	if parent != "" {
		insert = s.Store.ReplaceToken
	}
	if err := insert(r.Context(), store.Token{
		ID:         id,
		SecretHash: secretHash,
		AccountID:  account.ID,
		Name:       name,
		Audience:   audience,
		ParentID:   parent,
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
