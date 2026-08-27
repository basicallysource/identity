// identityd is the whole service: one binary, one SQLite file, an HTTP
// surface. Configuration is environment variables, because the places this
// runs -- a systemd unit, a container, a laptop -- all speak them:
//
//	IDENTITY_ADDR                   listen address       (default :8870)
//	IDENTITY_DB                     SQLite path          (default identity.db)
//	IDENTITY_BASE_URL               public base URL      (default http://localhost:8870)
//	IDENTITY_GITHUB_CLIENT_ID       GitHub OAuth app with device flow enabled
//	IDENTITY_DISCORD_CLIENT_ID      Discord application
//	IDENTITY_DISCORD_CLIENT_SECRET  its secret
//	IDENTITY_CLIENT_IP_HEADER       proxy header carrying the real client IP
//	IDENTITY_REDIRECT_ALLOW         comma-separated URL prefixes handoffs may go to
//
// A provider with no credentials set is simply not offered. The Discord app
// must have BASE_URL/signin/discord/callback registered as a redirect.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/basicallysource/identity/internal/api"
	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := env("IDENTITY_ADDR", ":8870")
	dbPath := env("IDENTITY_DB", "identity.db")
	baseURL := strings.TrimSuffix(env("IDENTITY_BASE_URL", "http://localhost:8870"), "/")

	db, err := store.Open(dbPath)
	if err != nil {
		logger.Error("open store", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	server := &api.Server{
		Store:  db,
		GitHub: &provider.GitHub{ClientID: os.Getenv("IDENTITY_GITHUB_CLIENT_ID")},
		Discord: &provider.Discord{
			ClientID:     os.Getenv("IDENTITY_DISCORD_CLIENT_ID"),
			ClientSecret: os.Getenv("IDENTITY_DISCORD_CLIENT_SECRET"),
		},
		BaseURL:        baseURL,
		ClientIPHeader: os.Getenv("IDENTITY_CLIENT_IP_HEADER"),
		RedirectAllow:  splitList(os.Getenv("IDENTITY_REDIRECT_ALLOW")),
		Logger:         logger,
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("identityd listening",
			"version", version, "addr", addr, "db", dbPath,
			"github", server.GitHub.Configured(), "discord", server.Discord.Configured())
		if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve", "error", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// splitList reads a comma-separated variable into its trimmed parts.
func splitList(value string) []string {
	var parts []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}
