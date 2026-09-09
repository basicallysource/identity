package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
)

// The page: server-rendered HTML, with htmx swapping in the parts that
// change without a reload. Every handler here is a thin face over the same
// operations the JSON API uses -- beginGitHub, redeemGitHub, beginDiscord,
// issue, mintHandoff, storeUploadedAvatar, the store -- so the page cannot
// come to do something the API does not.
//
// Under the CSP (script-src 'self') htmx runs from the embedded file with
// eval disabled; nothing here uses hx-on or a js: value. A cookie session
// is what authenticates these requests, and the secure middleware's
// same-origin check on writes is what keeps another site from driving
// them.

// authorizeCookie carries a consuming service's authorize request across
// the sign-in it triggered, so the person lands back where they were going.
const authorizeCookie = "identity_authorize"

// authorizeRequest is what a consuming service sends the browser here with.
type authorizeRequest struct {
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
}

// Host is where the person will be sent, for the page to say so.
func (a authorizeRequest) Host() string { return redirectHost(a.RedirectURI) }

// The page has tabs, one URL each, plain links between them: "account" at
// / is everybody's, "groups" at /groups is identity-admin's. A tab is a
// full page render; only the parts inside a tab change without a reload.
const (
	tabAccount = "account"
	tabGroups  = "groups"
)

// view is everything a template can see. Fragments use the slice of it
// they need; the full page gets all of it.
type view struct {
	Me        *whoamiResponse
	Tab       string
	Providers map[string]bool
	Tokens    []tokenRow
	Admin     bool
	Groups    []groupBody
	Audit     []auditBody
	Group     *groupDetailBody
	Accounts  []accountBody
	Device    *provider.Device
	Authorize *authorizeRequest
	Error     string
	Minted    string
}

func (s *Server) providerFlags() map[string]bool {
	return map[string]bool{"github": s.GitHub.Configured(), "discord": s.Discord.Configured()}
}

// viewer resolves the signed-in person for the page, or nil signed out.
func (s *Server) viewer(r *http.Request) (store.Account, store.Token, bool) {
	account, credential, err := s.authenticate(r)
	return account, credential, err == nil
}

// signedInView gathers everything the signed-in page shows.
func (s *Server) signedInView(r *http.Request, account store.Account, credential store.Token) (view, error) {
	me, err := s.describe(r.Context(), account, credential)
	if err != nil {
		return view{}, err
	}
	tokens, err := s.tokenRows(r.Context(), account, credential)
	if err != nil {
		return view{}, err
	}
	v := view{Me: &me, Tab: tabAccount, Providers: s.providerFlags(), Tokens: tokens}
	for _, g := range me.Groups {
		if g == store.AdminGroup {
			v.Admin = true
		}
	}
	return v, nil
}

// groupsPage is the groups tab, for identity-admin. Anybody else is sent
// to the account tab, which is the only one they have.
func (s *Server) groupsPage(w http.ResponseWriter, r *http.Request) {
	account, credential, signedIn := s.viewer(r)
	if !signedIn {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	v, err := s.signedInView(r, account, credential)
	if err != nil {
		s.logger().Error("page: groups", "error", err)
		s.render(w, http.StatusInternalServerError, "page", view{Providers: s.providerFlags(), Error: "could not read the account"})
		return
	}
	if !v.Admin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	v.Tab = tabGroups
	if err := s.fillGroups(r, &v); err != nil {
		s.logger().Error("page: groups", "error", err)
		v.Error = "could not read the groups"
	}
	s.render(w, http.StatusOK, "page", v)
}

func (s *Server) fillGroups(r *http.Request, v *view) error {
	groups, err := s.Store.Groups(r.Context())
	if err != nil {
		return err
	}
	v.Groups = []groupBody{}
	for _, g := range groups {
		v.Groups = append(v.Groups, describeGroup(g))
	}
	entries, err := s.Store.Audit(r.Context(), 30)
	if err != nil {
		return err
	}
	v.Audit = []auditBody{}
	for _, e := range entries {
		v.Audit = append(v.Audit, auditBody{ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, Group: e.Group, Account: e.AccountID, Handle: e.Handle})
	}
	return nil
}

func (s *Server) readAuthorize(r *http.Request) *authorizeRequest {
	c, err := r.Cookie(authorizeCookie)
	if err != nil || c.Value == "" {
		return nil
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return nil
	}
	var a authorizeRequest
	if json.Unmarshal([]byte(raw), &a) != nil || a.RedirectURI == "" {
		return nil
	}
	return &a
}

func (s *Server) setAuthorize(w http.ResponseWriter, a *authorizeRequest) {
	value, maxAge := "", -1
	if a != nil {
		raw, _ := json.Marshal(a)
		value, maxAge = url.QueryEscape(string(raw)), 600
	}
	http.SetCookie(w, &http.Cookie{Name: authorizeCookie, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: strings.HasPrefix(s.BaseURL, "https://"), SameSite: http.SameSiteLaxMode})
}

// page is GET / and GET /authorize. A consuming service's authorize request
// is finished here the moment there is a session for it: mint the code and
// send the browser back. Without a session, the request is kept in a
// cookie and the sign-in view says where the person is headed.
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	pending := s.readAuthorize(r)
	if q := r.URL.Query(); q.Get("redirect_uri") != "" {
		pending = &authorizeRequest{RedirectURI: q.Get("redirect_uri"), State: q.Get("state"), CodeChallenge: q.Get("code_challenge")}
		if !s.redirectAllowed(pending.RedirectURI) {
			s.setAuthorize(w, nil)
			s.render(w, http.StatusForbidden, "page", view{Providers: s.providerFlags(), Error: "sign-ins are not handed off to that destination"})
			return
		}
	}

	account, credential, signedIn := s.viewer(r)
	if signedIn && pending != nil {
		code, fail := s.mintHandoff(account, credential, pending.RedirectURI, pending.CodeChallenge)
		s.setAuthorize(w, nil)
		if fail != nil {
			s.render(w, fail.status, "page", view{Providers: s.providerFlags(), Error: fail.message})
			return
		}
		glue := "?"
		if strings.Contains(pending.RedirectURI, "?") {
			glue = "&"
		}
		http.Redirect(w, r, pending.RedirectURI+glue+"code="+url.QueryEscape(code)+"&state="+url.QueryEscape(pending.State), http.StatusSeeOther)
		return
	}
	if pending != nil {
		s.setAuthorize(w, pending)
	}
	if !signedIn {
		s.render(w, http.StatusOK, "page", view{Providers: s.providerFlags(), Authorize: pending})
		return
	}
	v, err := s.signedInView(r, account, credential)
	if err != nil {
		s.logger().Error("page", "error", err)
		s.render(w, http.StatusInternalServerError, "page", view{Providers: s.providerFlags(), Error: "could not read the account"})
		return
	}
	s.render(w, http.StatusOK, "page", v)
}

// -- signing in ---------------------------------------------------------

func (s *Server) uiGitHubStart(w http.ResponseWriter, r *http.Request) {
	device, fail := s.beginGitHub(r)
	if fail != nil {
		s.renderFailure(w, r, fail)
		return
	}
	s.render(w, http.StatusOK, "device", view{Device: &device, Authorize: s.readAuthorize(r)})
}

// uiGitHubPoll is what the device view asks every few seconds. The device
// details ride along in the form so the view can be re-rendered as is.
func (s *Server) uiGitHubPoll(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	device := provider.Device{
		DeviceCode:      r.Form.Get("device_code"),
		UserCode:        r.Form.Get("user_code"),
		VerificationURI: r.Form.Get("verification_uri"),
		Interval:        atoi(r.Form.Get("interval"), 5),
	}
	if device.DeviceCode == "" {
		s.renderFailure(w, r, &failure{http.StatusBadRequest, "that sign-in did not start here; start again", ""})
		return
	}
	user, linkTo, pending, slow, fail := s.redeemGitHub(r, device.DeviceCode)
	switch {
	case fail != nil:
		s.renderFailure(w, r, fail)
	case pending:
		if slow {
			device.Interval += 5
		}
		s.render(w, http.StatusOK, "device", view{Device: &device, Authorize: s.readAuthorize(r)})
	case linkTo != "":
		if err := s.completeLink(r, linkTo, provider.NameGitHub, user); err != nil {
			s.renderFailure(w, r, err)
			return
		}
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
	default:
		account, err := s.completeSignIn(r, provider.NameGitHub, user)
		if err != nil {
			s.renderFailure(w, r, err)
			return
		}
		minted, issueErr := s.issue(r, account, "", "")
		if issueErr != nil {
			s.renderFailure(w, r, &failure{http.StatusForbidden, issueErr.Error(), ""})
			return
		}
		s.setSession(w, minted.Token, *minted.ExpiresAt)
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
	}
}

// uiDiscordStart is a plain form post: the browser follows the redirect to
// Discord, and Discord's callback sends it back to /.
func (s *Server) uiDiscordStart(w http.ResponseWriter, r *http.Request) {
	target, fail := s.beginDiscord(w, r)
	if fail != nil {
		s.render(w, fail.status, "page", view{Providers: s.providerFlags(), Authorize: s.readAuthorize(r), Error: fail.message})
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func (s *Server) uiSignOut(w http.ResponseWriter, r *http.Request) {
	if account, credential, ok := s.viewer(r); ok {
		s.Store.RevokeToken(r.Context(), account.ID, credential.ID)
	}
	s.setSession(w, "", time.Unix(1, 0))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// -- the signed-in sections ---------------------------------------------

// section re-renders one named fragment of the signed-in page for the
// caller, with an optional message. Anything that changes the account
// answers this way, so the page never shows a stale section.
func (s *Server) section(w http.ResponseWriter, r *http.Request, name string, fail *failure, minted string) {
	account, credential, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	v, err := s.signedInView(r, account, credential)
	if err != nil {
		s.logger().Error("page: "+name, "error", err)
		v = view{Error: "could not read the account"}
	}
	status := http.StatusOK
	if fail != nil {
		v.Error, status = fail.message, fail.status
	}
	v.Minted = minted
	s.render(w, status, name, v)
}

func (s *Server) uiMintToken(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	r.ParseForm()
	name := strings.TrimSpace(r.Form.Get("name"))
	if name == "" {
		name = "token"
	}
	minted, err := s.issue(r, account, name, "")
	if err != nil {
		s.section(w, r, "tokens", &failure{http.StatusForbidden, err.Error(), ""}, "")
		return
	}
	s.section(w, r, "tokens", nil, minted.Token)
}

func (s *Server) uiRevokeToken(w http.ResponseWriter, r *http.Request) {
	account, credential, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	id := r.PathValue("id")
	if err := s.Store.RevokeToken(r.Context(), account.ID, id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.section(w, r, "tokens", &failure{http.StatusInternalServerError, "could not revoke the token", ""}, "")
		return
	}
	if id == credential.ID {
		// They revoked the session they are using. Send them to the front.
		s.setSession(w, "", time.Unix(1, 0))
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.section(w, r, "tokens", nil, "")
}

func (s *Server) uiUploadAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.avatar_mu.TryLock() {
		s.section(w, r, "photo", &failure{503, "another photo is processing; try again shortly", ""}, "")
		return
	}
	defer s.avatar_mu.Unlock()
	if fail := s.avatarAttempt(account); fail != nil {
		s.section(w, r, "photo", fail, "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MAX_AVATAR_BYTES+64<<10)
	file, header, err := r.FormFile("photo")
	if err != nil {
		s.section(w, r, "photo", &failure{413, "choose an image no larger than 5 MiB", ""}, "")
		return
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, MAX_AVATAR_BYTES+1))
	if err != nil {
		s.section(w, r, "photo", &failure{413, "choose an image no larger than 5 MiB", ""}, "")
		return
	}
	content_type, _, _ := mime.ParseMediaType(header.Header.Get("Content-Type"))
	if _, fail := s.storeUploadedAvatar(r.Context(), account, raw, content_type); fail != nil {
		s.section(w, r, "photo", fail, "")
		return
	}
	s.section(w, r, "photo", nil, "")
}

func (s *Server) uiSelectAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	r.ParseForm()
	if err := s.Store.SelectAvatar(r.Context(), account.ID, r.Form.Get("source")); err != nil {
		s.section(w, r, "photo", &failure{400, "choose one of your available profile photos", ""}, "")
		return
	}
	s.section(w, r, "photo", nil, "")
}

func (s *Server) uiDeleteAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := s.Store.SetAvatar(r.Context(), account.ID, "", 0, 0); err != nil {
		s.section(w, r, "photo", &failure{500, "could not remove the profile photo", ""}, "")
		return
	}
	s.section(w, r, "photo", nil, "")
}

// -- groups, for identity-admin -----------------------------------------

// admin is requireAdmin for the page: the refusal is a fragment, and a
// signed-out caller is sent to the front.
func (s *Server) admin(w http.ResponseWriter, r *http.Request) (store.Account, bool) {
	account, _, ok := s.viewer(r)
	if !ok {
		w.Header().Set("HX-Redirect", "/")
		w.WriteHeader(http.StatusNoContent)
		return store.Account{}, false
	}
	isAdmin, err := s.Store.IsMember(r.Context(), store.AdminGroup, account.ID)
	if err != nil || !isAdmin {
		s.render(w, http.StatusForbidden, "error", view{Error: "managing groups requires membership of " + store.AdminGroup})
		return store.Account{}, false
	}
	return account, true
}

// groupsSection renders the groups list and audit log, with a message.
func (s *Server) groupsSection(w http.ResponseWriter, r *http.Request, fail *failure) {
	v := view{Admin: true}
	if err := s.fillGroups(r, &v); err != nil {
		s.logger().Error("page: groups", "error", err)
		v.Error = "could not read the groups"
	}
	status := http.StatusOK
	if fail != nil {
		v.Error, status = fail.message, fail.status
	}
	s.render(w, status, "groups", v)
}

// groupSection renders one group's detail, with a message.
func (s *Server) groupSection(w http.ResponseWriter, r *http.Request, name string, fail *failure) {
	g, members, err := s.Store.Group(r.Context(), name)
	if errors.Is(err, store.ErrNotFound) {
		s.render(w, http.StatusNotFound, "error", view{Error: "no such group"})
		return
	}
	if err != nil {
		s.logger().Error("page: group", "error", err)
		s.render(w, http.StatusInternalServerError, "error", view{Error: "could not read the group"})
		return
	}
	detail := groupDetailBody{Name: g.Name, Description: g.Description, CreatedAt: g.CreatedAt, CreatedBy: g.CreatedBy, Members: []memberBody{}}
	for _, m := range members {
		detail.Members = append(detail.Members, memberBody{Account: m.AccountID, Handle: m.Handle, AddedAt: m.AddedAt, AddedBy: m.AddedBy})
	}
	v := view{Admin: true, Group: &detail}
	status := http.StatusOK
	if fail != nil {
		v.Error, status = fail.message, fail.status
	}
	s.render(w, status, "group", v)
}

func (s *Server) uiCreateGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	name := strings.TrimSpace(r.Form.Get("name"))
	err := s.Store.CreateGroup(r.Context(), name, r.Form.Get("description"), actor.ID)
	switch {
	case errors.Is(err, store.ErrBadGroupName):
		s.groupsSection(w, r, &failure{http.StatusBadRequest, "a group name is 1 to 63 lowercase letters, digits and hyphens, starting with a letter or digit", ""})
	case errors.Is(err, store.ErrExists):
		s.groupsSection(w, r, &failure{http.StatusConflict, "a group with that name already exists", ""})
	case err != nil:
		s.logger().Error("groups: create", "error", err)
		s.groupsSection(w, r, &failure{http.StatusInternalServerError, "could not create the group", ""})
	default:
		s.logger().Info("created a group", "group", name, "by", actor.ID)
		s.groupsSection(w, r, nil)
	}
}

func (s *Server) uiGroup(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admin(w, r); !ok {
		return
	}
	s.groupSection(w, r, r.PathValue("name"), nil)
}

func (s *Server) uiDeleteGroup(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	err := s.Store.DeleteGroup(r.Context(), name, actor.ID)
	switch {
	case errors.Is(err, store.ErrReservedGroup):
		s.groupSection(w, r, name, &failure{http.StatusForbidden, store.AdminGroup + " cannot be deleted", ""})
	case errors.Is(err, store.ErrNotFound):
		s.groupsSection(w, r, &failure{http.StatusNotFound, "no such group", ""})
	case err != nil:
		s.logger().Error("groups: delete", "error", err)
		s.groupSection(w, r, name, &failure{http.StatusInternalServerError, "could not delete the group", ""})
	default:
		s.logger().Info("deleted a group", "group", name, "by", actor.ID)
		s.groupsSection(w, r, nil)
	}
}

func (s *Server) uiAddMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	name, account := r.PathValue("name"), r.PathValue("account")
	err := s.Store.AddMember(r.Context(), name, account, actor.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.groupSection(w, r, name, &failure{http.StatusNotFound, "no such group or account", ""})
	case err != nil:
		s.logger().Error("groups: add member", "error", err)
		s.groupSection(w, r, name, &failure{http.StatusInternalServerError, "could not add the member", ""})
	default:
		s.logger().Info("added a member", "group", name, "account", account, "by", actor.ID)
		s.groupSection(w, r, name, nil)
	}
}

func (s *Server) uiRemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.admin(w, r)
	if !ok {
		return
	}
	name, account := r.PathValue("name"), r.PathValue("account")
	err := s.Store.RemoveMember(r.Context(), name, account, actor.ID)
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		s.groupSection(w, r, name, &failure{http.StatusForbidden, "that would leave " + store.AdminGroup + " empty; add another administrator first", ""})
	case errors.Is(err, store.ErrNotFound):
		s.groupSection(w, r, name, &failure{http.StatusNotFound, "that account is not in that group", ""})
	case err != nil:
		s.logger().Error("groups: remove member", "error", err)
		s.groupSection(w, r, name, &failure{http.StatusInternalServerError, "could not remove the member", ""})
	default:
		s.logger().Info("removed a member", "group", name, "account", account, "by", actor.ID)
		s.groupSection(w, r, name, nil)
	}
}

// uiSearchAccounts answers the add-a-person search box inside a group with
// matches and an add button on each, marking the ones already in it.
func (s *Server) uiSearchAccounts(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.admin(w, r); !ok {
		return
	}
	q := r.URL.Query()
	matches, err := s.Store.SearchAccounts(r.Context(), strings.TrimSpace(q.Get("q")), 10)
	if err != nil {
		s.render(w, http.StatusInternalServerError, "error", view{Error: "could not search accounts"})
		return
	}
	v := view{Admin: true, Group: &groupDetailBody{Name: q.Get("group")}, Accounts: []accountBody{}}
	for _, m := range matches {
		groups, _ := s.Store.GroupsFor(r.Context(), m.Account.ID)
		body := accountBody{Account: m.Account.ID, Handle: m.Account.Handle, CreatedAt: m.Account.CreatedAt, Identities: []identityBody{}, Groups: groups}
		for _, identity := range m.Identities {
			body.Identities = append(body.Identities, identityBody{Provider: identity.Provider, ID: identity.ProviderID, Handle: identity.Handle, ProvedAt: identity.ProvedAt})
		}
		v.Accounts = append(v.Accounts, body)
	}
	s.render(w, http.StatusOK, "accounts", v)
}

// renderFailure answers a sign-in step that failed with the signed-out view
// and the reason, in place of whatever the browser was showing.
func (s *Server) renderFailure(w http.ResponseWriter, r *http.Request, fail *failure) {
	s.render(w, fail.status, "signed_out", view{Providers: s.providerFlags(), Authorize: s.readAuthorize(r), Error: fail.message})
}

func atoi(value string, fallback int) int {
	n := 0
	for _, c := range value {
		if c < '0' || c > '9' {
			return fallback
		}
		n = n*10 + int(c-'0')
		if n > 3600 {
			return fallback
		}
	}
	if value == "" {
		return fallback
	}
	return n
}
