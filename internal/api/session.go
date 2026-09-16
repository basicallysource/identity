package api

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) https() bool { return strings.HasPrefix(s.BaseURL, "https://") }

func (s *Server) sessionName() string {
	if s.https() {
		return "__Host-identity"
	}
	return "identity_session"
}

// cookieName is what a cookie this service sets is called on this
// deployment. On https it carries the __Host- prefix, which a browser only
// accepts from this exact host, Secure, with Path=/ and no Domain, so a
// sibling subdomain cannot plant one to steer a sign-in here. Plain http is
// local development, where the prefix cannot be set.
func (s *Server) cookieName(name string) string {
	if s.https() {
		return "__Host-" + name
	}
	return name
}

func (s *Server) setSession(w http.ResponseWriter, bearer string, expires time.Time) {
	max_age := int(expires.Sub(s.now()).Seconds())
	if bearer == "" {
		max_age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionName(), Value: bearer, Path: "/", Expires: expires, MaxAge: max_age, HttpOnly: true, Secure: s.https(), SameSite: http.SameSiteLaxMode})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	account, credential, err := s.authenticate(r)
	if err == nil {
		if err := s.Store.RevokeToken(r.Context(), account.ID, credential.ID); err != nil {
			writeError(w, 500, "could not sign out")
			return
		}
	}
	s.setSession(w, "", time.Unix(1, 0))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) secure(next http.Handler) http.Handler {
	// The Discord button is a form post answered with a redirect to Discord,
	// and a browser refuses that redirect unless form-action allows it.
	formAction := "'self'"
	if s.Discord.Configured() {
		formAction += " " + s.Discord.AuthorizeOrigin()
	}
	csp := "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action " + formAction
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// same-origin, not no-referrer: under no-referrer a browser sends
		// Origin: null on the page's plain form posts (sign out, Discord),
		// which the check below refuses. Other origins get no referrer either
		// way.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", csp)
		cookie, cookie_err := r.Cookie(s.sessionName())
		// A write from a browser must come from this service's own page. The
		// page's routes are a browser's whether or not a cookie rides along:
		// the GitHub poll signs a browser in without one, which is exactly the
		// request a foreign page would forge to sign its visitor in as
		// somebody else.
		page := strings.HasPrefix(r.URL.Path, "/ui/") || strings.HasPrefix(r.URL.Path, "/session/")
		browser := page || r.Header.Get("X-Identity-Browser") == "1" || (cookie_err == nil && r.Header.Get("Authorization") == "")
		if browser && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("Origin") != s.BaseURL {
			writeError(w, http.StatusForbidden, "same-origin request required")
			return
		}
		if cookie_err == nil && r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+cookie.Value)
			if _, credential, err := s.authenticate(r); err != nil || credential.Audience != "" {
				r.Header.Del("Authorization")
				s.setSession(w, "", time.Unix(1, 0))
			}
		}
		_, credential, err := s.authenticate(r)
		if err == nil && credential.Audience != "" && r.URL.Path != "/v1/whoami" && r.URL.Path != "/v1/avatar" {
			own := r.Method == http.MethodDelete && r.URL.Path == "/v1/tokens/"+credential.ID
			signout := r.Method == http.MethodPost && r.URL.Path == "/v1/signout"
			if !own && !signout {
				writeError(w, http.StatusForbidden, "application tokens cannot manage the account or sign in to another application")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
