package api

import (
	"net/http"
	"strings"
	"time"
)

func (s *Server) sessionName() string {
	if strings.HasPrefix(s.BaseURL, "https://") {
		return "__Host-identity"
	}
	return "identity_session"
}

func (s *Server) setSession(w http.ResponseWriter, bearer string, expires time.Time) {
	max_age := int(expires.Sub(s.now()).Seconds())
	if bearer == "" {
		max_age = -1
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionName(), Value: bearer, Path: "/", Expires: expires, MaxAge: max_age, HttpOnly: true, Secure: strings.HasPrefix(s.BaseURL, "https://"), SameSite: http.SameSiteLaxMode})
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		cookie, cookie_err := r.Cookie(s.sessionName())
		browser := r.Header.Get("X-Identity-Browser") == "1" || (cookie_err == nil && r.Header.Get("Authorization") == "")
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
		if err == nil && credential.Audience != "" && r.URL.Path != "/v1/whoami" {
			if !(r.Method == http.MethodDelete && r.URL.Path == "/v1/tokens/"+credential.ID) {
				writeError(w, http.StatusForbidden, "application tokens cannot manage the account or sign in to another application")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
