package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Discord proves identities with the standard authorization-code redirect,
// because Discord offers no device flow. It does OAuth2 but not real OIDC --
// there is no id_token -- so the proof is the same shape as GitHub's: use the
// access token once to ask /users/@me who it belongs to, then drop it.
type Discord struct {
	ClientID string
	// ClientSecret is required by Discord's token exchange; the redirect
	// flow is a confidential client, unlike GitHub's device flow.
	ClientSecret string

	HTTP         *http.Client
	AuthorizeURL string
	TokenURL     string
	UserURL      string
}

// Discord's endpoints, overridable so a test can point them somewhere else.
const (
	defaultDiscordAuthorizeURL = "https://discord.com/oauth2/authorize"
	defaultDiscordTokenURL     = "https://discord.com/api/oauth2/token"
	defaultDiscordUserURL      = "https://discord.com/api/users/@me"
)

// Configured reports whether sign-in can be offered.
func (d *Discord) Configured() bool {
	return d != nil && strings.TrimSpace(d.ClientID) != "" && strings.TrimSpace(d.ClientSecret) != ""
}

// Authorize is where to send the person's browser. State ties the eventual
// callback to the browser that started it; redirectURI must match what the
// Discord application has registered, exactly.
func (d *Discord) Authorize(state, redirectURI string) string {
	query := url.Values{
		"response_type": {"code"},
		"client_id":     {d.ClientID},
		// identify is the smallest scope Discord has: id and username,
		// nothing else. This service needs nothing else.
		"scope":        {"identify"},
		"state":        {state},
		"redirect_uri": {redirectURI},
	}
	return pick(d.AuthorizeURL, defaultDiscordAuthorizeURL) + "?" + query.Encode()
}

// Redeem exchanges a callback's code for the identity behind it.
func (d *Discord) Redeem(ctx context.Context, code, redirectURI string) (User, error) {
	if !d.Configured() {
		return User{}, ErrUnconfigured
	}

	form := url.Values{
		"client_id":     {d.ClientID},
		"client_secret": {d.ClientSecret},
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}

	var response struct {
		AccessToken string `json:"access_token"`
	}
	if err := postForm(ctx, d.client(), pick(d.TokenURL, defaultDiscordTokenURL), form, &response); err != nil {
		return User{}, err
	}
	if response.AccessToken == "" {
		return User{}, errors.New("provider: Discord returned no token for the code")
	}

	return d.user(ctx, response.AccessToken)
}

// user asks who a token belongs to, and is the only thing that token is ever
// used for.
func (d *Discord) user(ctx context.Context, token string) (User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pick(d.UserURL, defaultDiscordUserURL), nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := d.client().Do(req)
	if err != nil {
		return User{}, fmt.Errorf("provider: ask Discord who this is: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("provider: Discord answered %d asking who this is", resp.StatusCode)
	}

	var body struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return User{}, fmt.Errorf("provider: read Discord's answer: %w", err)
	}
	if body.ID == "" || body.Username == "" {
		return User{}, errors.New("provider: Discord returned an empty identity")
	}
	return User{ID: body.ID, Handle: body.Username}, nil
}

func (d *Discord) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}
