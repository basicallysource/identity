package token

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	minted, id, secretHash, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(minted, Prefix+"_") {
		t.Fatalf("token %q lacks the prefix", minted)
	}

	parsedID, secret, ok := Parse(minted)
	if !ok {
		t.Fatalf("minted token %q does not parse", minted)
	}
	if parsedID != id {
		t.Fatalf("parsed id %q, minted %q", parsedID, id)
	}
	if !Matches(secret, secretHash) {
		t.Fatal("minted secret does not match its own hash")
	}
	if Matches(secret+"x", secretHash) {
		t.Fatal("a tampered secret matched")
	}
}

func TestParseRejectsForeignShapes(t *testing.T) {
	for _, bad := range []string{
		"", "bsid", "bsid_", "bsid_only", "bsid__secret", "bsid_id_",
		"asset_abcd_efgh", "Bearer bsid_a_b",
	} {
		if _, _, ok := Parse(bad); ok {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
}
