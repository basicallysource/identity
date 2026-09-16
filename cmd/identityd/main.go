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
//	IDENTITY_REDIRECT_ALLOW         comma-separated callback URLs handoffs may go to
//	IDENTITY_ASSET_URL              asset-service API origin
//	IDENTITY_ASSET_TOKEN            scoped profile-photo service credential
//	IDENTITY_ASSET_NAMESPACE        private profile-photo namespace
//	IDENTITY_STORAGE_ORIGIN         private asset storage origin
//
// A provider with no credentials set is simply not offered. The Discord app
// must have BASE_URL/signin/discord/callback registered as a redirect.
//
// With no arguments it serves. With arguments it is the operator's command
// against the same database, for the things that must work with nobody
// signed in -- above all the first identity-admin, without whom the groups
// page has no administrator to open it:
//
//	identityd accounts                    list every account and its identities
//	identityd groups                      list every group and its members
//	identityd grant <group> <account>     add to a group, creating the group if needed
//	identityd revoke <group> <account>    remove from a group
//
// <account> is an account id or a handle that names exactly one account.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/basicallysource/identity/internal/api"
	"github.com/basicallysource/identity/internal/avatar"
	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
)

var version = "dev"

func main() {
	dbPath := env("IDENTITY_DB", "identity.db")
	if len(os.Args) > 1 {
		if err := command(dbPath, os.Args[1], os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "identityd:", err)
			os.Exit(1)
		}
		return
	}
	serve(dbPath)
}

func serve(dbPath string) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	addr := env("IDENTITY_ADDR", ":8870")
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
	if os.Getenv("IDENTITY_ASSET_URL") != "" {
		server.Avatars, err = avatar.New(strings.TrimRight(os.Getenv("IDENTITY_ASSET_URL"), "/"), os.Getenv("IDENTITY_ASSET_TOKEN"), env("IDENTITY_ASSET_NAMESPACE", "profile-avatars"), strings.TrimRight(os.Getenv("IDENTITY_STORAGE_ORIGIN"), "/"))
		if err != nil {
			logger.Error("avatar configuration", "error", err)
			os.Exit(1)
		}
	}

	httpServer := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       60 * time.Second,
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

// cliActor is what the audit log records for a change made at the terminal
// rather than by a signed-in account.
const cliActor = "cli"

// command is the operator surface. It opens the database directly, so it
// works on the box with the service stopped or running, and needs no token.
func command(dbPath, name string, args []string) error {
	db, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx := context.Background()

	switch name {
	case "accounts":
		for offset := 0; ; offset += 100 {
			matches, _, err := db.SearchAccounts(ctx, "", offset, 100)
			if err != nil {
				return err
			}
			for _, m := range matches {
				var proofs []string
				for _, i := range m.Identities {
					proofs = append(proofs, i.Provider+":"+i.Handle)
				}
				groups, _ := db.GroupsFor(ctx, m.Account.ID)
				fmt.Printf("%s  %-24s  %-40s  %s\n", m.Account.ID, m.Account.Handle, strings.Join(proofs, " "), strings.Join(groups, ","))
			}
			if len(matches) < 100 {
				return nil
			}
		}

	case "groups":
		groups, err := db.Groups(ctx)
		if err != nil {
			return err
		}
		for _, g := range groups {
			_, members, err := db.Group(ctx, g.Name)
			if err != nil {
				return err
			}
			var handles []string
			for _, m := range members {
				handles = append(handles, m.Handle)
			}
			fmt.Printf("%-24s  %d  %s\n", g.Name, len(members), strings.Join(handles, ", "))
		}
		return nil

	case "grant", "revoke":
		if len(args) != 2 {
			return fmt.Errorf("usage: identityd %s <group> <account-id-or-handle>", name)
		}
		group, who := args[0], args[1]
		account, err := db.ResolveAccount(ctx, who)
		if err != nil {
			return err
		}
		if name == "revoke" {
			if err := db.RemoveMember(ctx, group, account.ID, cliActor); err != nil {
				return err
			}
			fmt.Printf("removed %s (%s) from %s\n", account.Handle, account.ID, group)
			return nil
		}
		if err := db.CreateGroup(ctx, group, "", cliActor); err != nil && !errors.Is(err, store.ErrExists) {
			return err
		}
		if err := db.AddMember(ctx, group, account.ID, cliActor); err != nil {
			return err
		}
		fmt.Printf("added %s (%s) to %s\n", account.Handle, account.ID, group)
		return nil

	default:
		return fmt.Errorf("unknown command %q; commands are accounts, groups, grant, revoke", name)
	}
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
