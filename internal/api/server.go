// Package api is the HTTP surface: the sign-in flows, the whoami endpoint
// other services build their authentication on, and token management.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
	"github.com/basicallysource/identity/internal/token"
)

// Token policy. Tokens expire so a leaked one has a horizon, and the live
// count is capped so "make another one" cannot go on forever. Both are
// service-wide: this service has no tiers, because authorization is each
// consuming service's own business.
const (
	tokenLifetime  = 90 * 24 * time.Hour
	maxLiveTokens  = 25
	pendingFlowTTL = 15 * time.Minute
)

// Server is the HTTP API.
type Server struct {
	Store   *store.DB
	GitHub  *provider.GitHub
	Discord *provider.Discord
	// BaseURL is where this service lives publicly, for building the
	// Discord redirect. No trailing slash.
	BaseURL string
	// ClientIPHeader is the header a proxy in front of this service sets to
	// the real client address, e.g. CF-Connecting-IP. Empty trusts none,
	// which is the only safe default -- any caller can send a header.
	ClientIPHeader string
	// RedirectAllow is the URL prefixes a sign-in may be handed off to:
	// the consuming services' callback origins. Empty disables handoff.
	RedirectAllow []string
	Logger        *slog.Logger
	// Now is the clock, swapped in tests.
	Now func() time.Time

	// pending ties multi-step flows together across requests: a device code
	// or an OAuth state, and -- when the flow is a link rather than a
	// sign-in -- the account it must attach to. In memory on purpose: a
	// restart forgets half-finished sign-ins, which cost one retry.
	mu      sync.Mutex
	pending map[string]pendingFlow

	throttle throttle
}

type pendingFlow struct {
	accountID   string
	redirectURI string
	expires     time.Time
}

// Handler builds the routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", s.page)
	// The page itself handles an authorize request; the route exists so a
	// consuming service has a name to send the browser to.
	mux.HandleFunc("GET /authorize", s.page)
	mux.HandleFunc("GET /style.css", s.stylesheet)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	mux.HandleFunc("POST /signin/github/start", s.githubStart)
	mux.HandleFunc("POST /signin/github/finish", s.githubFinish)
	mux.HandleFunc("POST /signin/discord/start", s.discordStart)
	mux.HandleFunc("GET /signin/discord/callback", s.discordCallback)

	mux.HandleFunc("GET /v1/whoami", s.whoami)
	mux.HandleFunc("POST /v1/handoff", s.handoff)
	mux.HandleFunc("POST /v1/exchange", s.exchange)
	mux.HandleFunc("GET /v1/tokens", s.listTokens)
	mux.HandleFunc("POST /v1/tokens", s.mintToken)
	mux.HandleFunc("DELETE /v1/tokens/{id}", s.revokeToken)

	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

// authenticate resolves a bearer token to the account behind it. It returns
// store.ErrNotFound for anything short of a live, well-formed credential; a
// request with no Authorization header at all gets errNoCredentials.
var errNoCredentials = errors.New("api: no credentials")

func (s *Server) authenticate(r *http.Request) (store.Account, store.Token, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return store.Account{}, store.Token{}, errNoCredentials
	}
	bearer, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return store.Account{}, store.Token{}, store.ErrNotFound
	}

	id, secret, ok := token.Parse(strings.TrimSpace(bearer))
	if !ok {
		return store.Account{}, store.Token{}, store.ErrNotFound
	}
	stored, err := s.Store.TokenByID(r.Context(), id)
	if err != nil {
		// A missing id and a wrong secret are the same answer on purpose.
		return store.Account{}, store.Token{}, store.ErrNotFound
	}
	if !token.Matches(secret, stored.SecretHash) || !stored.Live(s.now()) {
		return store.Account{}, store.Token{}, store.ErrNotFound
	}

	account, err := s.Store.AccountByID(r.Context(), stored.AccountID)
	if err != nil {
		return store.Account{}, store.Token{}, store.ErrNotFound
	}
	return account, stored, nil
}

// remember stores one half-finished flow under a key.
func (s *Server) remember(key, accountID string) {
	s.rememberFlow(key, pendingFlow{accountID: accountID}, pendingFlowTTL)
}

func (s *Server) rememberFlow(key string, flow pendingFlow, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending == nil {
		s.pending = make(map[string]pendingFlow)
	}
	now := s.now()
	for k, pending := range s.pending {
		if pending.expires.Before(now) {
			delete(s.pending, k)
		}
	}
	flow.expires = now.Add(ttl)
	s.pending[key] = flow
}

// recall consumes a half-finished flow. The second result is whether the key
// was known at all.
func (s *Server) recall(key string) (pendingFlow, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.pending[key]
	if ok {
		delete(s.pending, key)
	}
	if !ok || flow.expires.Before(s.now()) {
		return pendingFlow{}, false
	}
	return flow, true
}

// JSON responses, minimal on purpose.

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// newState mints an unguessable handle for a redirect flow.
func newState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("api: mint state: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// throttle is a small per-address sliding window for the endpoints that fan
// out to a provider, so an abuser burns their own patience and not this
// service's standing with GitHub or Discord.
type throttle struct {
	mu    sync.Mutex
	hits  map[string][]time.Time
	limit int
	per   time.Duration
}

func (t *throttle) allow(addr string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.limit == 0 {
		t.limit, t.per = 10, time.Minute
	}
	if t.hits == nil {
		t.hits = make(map[string][]time.Time)
	}

	cutoff := now.Add(-t.per)
	kept := t.hits[addr][:0]
	for _, hit := range t.hits[addr] {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= t.limit {
		t.hits[addr] = kept
		return false
	}
	t.hits[addr] = append(kept, now)

	// Forget quiet addresses so the map cannot grow without bound.
	if len(t.hits) > 4096 {
		for a, hits := range t.hits {
			if len(hits) == 0 || !hits[len(hits)-1].After(cutoff) {
				delete(t.hits, a)
			}
		}
	}
	return true
}

// clientAddr is the throttle key: the configured proxy header when there is
// one, else the peer address, without the port. Behind a proxy the peer is
// the proxy, and a throttle keyed on it would be one bucket for everybody.
func (s *Server) clientAddr(r *http.Request) string {
	if s.ClientIPHeader != "" {
		if value := r.Header.Get(s.ClientIPHeader); value != "" {
			// An X-Forwarded-For style header may carry a chain; the
			// client is the first hop.
			value, _, _ = strings.Cut(value, ",")
			return strings.TrimSpace(value)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
