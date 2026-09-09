// Package api is the contract: openapi.yaml, and a Go client generated from
// it. Consumers should not use this client directly; the client package
// wraps it with the handoff, the session cookie and the audience check, so
// the security rules are code you import rather than rules you remember.
//
// Regenerate after editing openapi.yaml, and commit the result:
//
//	go generate ./api
//
// CI fails if the committed code disagrees with the spec.
package api

//go:generate go tool oapi-codegen -config oapi-codegen.yaml openapi.yaml
