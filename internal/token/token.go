// Package token mints and checks the opaque bearer tokens this service
// issues. A token is "bsid_<id>_<secret>": the id is stored in the clear so a
// lookup is one indexed read, and the secret is stored only as a hash, so the
// database never holds anything worth stealing.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// Prefix marks this service's tokens wherever one turns up.
const Prefix = "bsid"

// New mints a credential. It returns the token to hand over once, the id to
// store in the clear, and the hash to store in place of the secret.
func New() (token, id, secretHash string, err error) {
	idBytes := make([]byte, 8)
	secretBytes := make([]byte, 32)
	if _, err = rand.Read(idBytes); err != nil {
		return "", "", "", err
	}
	if _, err = rand.Read(secretBytes); err != nil {
		return "", "", "", err
	}

	id = hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	return Prefix + "_" + id + "_" + secret, id, HashSecret(secret), nil
}

// Parse splits a token into its id and secret halves.
func Parse(token string) (id, secret string, ok bool) {
	parts := strings.SplitN(token, "_", 3)
	if len(parts) != 3 || parts[0] != Prefix || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// HashSecret is how a token's secret half is stored. A plain SHA-256 is
// correct here and a password KDF would not be: the secret is 32 bytes from
// crypto/rand, so there is no dictionary to run against it.
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Matches compares a presented secret against a stored hash in constant time.
func Matches(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(HashSecret(secret)), []byte(storedHash)) == 1
}
