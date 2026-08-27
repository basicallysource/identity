// Package provider proves who is asking, at the providers this service
// trusts to know: GitHub and Discord.
//
// A provider token is used exactly once, to ask the provider who it belongs
// to, and then dropped. This service never stores a credential for another
// system; it holds who people are, not the power to act as them.
package provider

import "errors"

// Names a provider goes by wherever an identity is recorded.
const (
	NameGitHub  = "github"
	NameDiscord = "discord"
)

// User is an identity as a provider reports it. ID is the provider's own
// immutable id (GitHub's numeric id, Discord's snowflake), because a login
// can be renamed and the old name taken by somebody else.
type User struct {
	ID     string
	Handle string
}

// ErrUnconfigured means the provider's client credentials were not set, so
// sign-in through it cannot be offered at all.
var ErrUnconfigured = errors.New("provider: not configured")
