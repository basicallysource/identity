package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// GitHub proves identities with the device flow, which is the right shape for
// every caller this service has: a person at a terminal, an agent working on
// their behalf, or a browser. There is no redirect to catch and no client
// secret to keep, because a device flow client is a public one -- the proof
// is that the person went to github.com and typed a code that only this
// exchange knows about.
type GitHub struct {
	// ClientID identifies the OAuth app. It is not a secret: a device flow
	// client is public by design, which is why there is no secret here.
	ClientID string

	HTTP      *http.Client
	DeviceURL string
	TokenURL  string
	UserURL   string
}

// GitHub's endpoints, overridable so a test can point them somewhere else.
const (
	defaultGitHubDeviceURL = "https://github.com/login/device/code"
	defaultGitHubTokenURL  = "https://github.com/login/oauth/access_token"
	defaultGitHubUserURL   = "https://api.github.com/user"
)

// What a redemption can say other than "here is who it is".
var (
	// ErrPending means the person has not finished at github.com yet. The
	// caller should poll again.
	ErrPending = errors.New("provider: authorization pending")
	// ErrSlowDown means polling too fast; wait longer than the interval.
	ErrSlowDown = errors.New("provider: polling too fast")
	// ErrExpired means the code timed out and a new one is needed.
	ErrExpired = errors.New("provider: device code expired")
	// ErrDenied means the person said no.
	ErrDenied = errors.New("provider: authorization denied")
)

// Device is what a caller shows a person so they can approve the request.
type Device struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// Configured reports whether sign-in can be offered.
func (g *GitHub) Configured() bool { return g != nil && strings.TrimSpace(g.ClientID) != "" }

// Start asks GitHub for a device code.
func (g *GitHub) Start(ctx context.Context) (Device, error) {
	if !g.Configured() {
		return Device{}, ErrUnconfigured
	}

	// No scopes: this only ever needs to know who someone is, and a token
	// that can do nothing else is a token worth nothing if it leaks.
	form := url.Values{"client_id": {g.ClientID}}

	var device Device
	if err := postForm(ctx, g.client(), pick(g.DeviceURL, defaultGitHubDeviceURL), form, &device); err != nil {
		return Device{}, err
	}
	if device.DeviceCode == "" || device.UserCode == "" {
		return Device{}, errors.New("provider: GitHub returned no device code")
	}
	if device.Interval <= 0 {
		device.Interval = 5
	}
	return device, nil
}

// Redeem exchanges an approved device code for the identity behind it.
func (g *GitHub) Redeem(ctx context.Context, deviceCode string) (User, error) {
	if !g.Configured() {
		return User{}, ErrUnconfigured
	}

	form := url.Values{
		"client_id":   {g.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	var response struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := postForm(ctx, g.client(), pick(g.TokenURL, defaultGitHubTokenURL), form, &response); err != nil {
		return User{}, err
	}

	switch response.Error {
	case "":
	case "authorization_pending":
		return User{}, ErrPending
	case "slow_down":
		return User{}, ErrSlowDown
	case "expired_token":
		return User{}, ErrExpired
	case "access_denied":
		return User{}, ErrDenied
	default:
		return User{}, fmt.Errorf("provider: GitHub said %q", response.Error)
	}
	if response.AccessToken == "" {
		return User{}, errors.New("provider: GitHub approved the code but returned no token")
	}

	return g.user(ctx, response.AccessToken)
}

// user asks who a token belongs to, and is the only thing that token is ever
// used for.
func (g *GitHub) user(ctx context.Context, token string) (User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pick(g.UserURL, defaultGitHubUserURL), nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := g.client().Do(req)
	if err != nil {
		return User{}, fmt.Errorf("provider: ask GitHub who this is: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("provider: GitHub answered %d asking who this is", resp.StatusCode)
	}

	var body struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return User{}, fmt.Errorf("provider: read GitHub's answer: %w", err)
	}
	if body.ID == 0 || body.Login == "" {
		return User{}, errors.New("provider: GitHub returned an empty identity")
	}
	return User{ID: strconv.FormatInt(body.ID, 10), Handle: body.Login}, nil
}

func (g *GitHub) client() *http.Client {
	if g.HTTP != nil {
		return g.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

// postForm posts a form and decodes a JSON answer, the shape both providers'
// token endpoints share.
func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("provider: reach %s: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("provider: %s answered %d", req.URL.Host, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into); err != nil {
		return fmt.Errorf("provider: read %s's answer: %w", req.URL.Host, err)
	}
	return nil
}

func pick(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}
