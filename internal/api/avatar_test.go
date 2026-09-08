package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/basicallysource/identity/internal/avatar"
)

func profileCredential(t *testing.T, s *Server, provider_id string) (string, string) {
	t.Helper()
	account, err := s.Store.SignIn(context.Background(), "github", provider_id, "reader-"+provider_id)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := s.issue(httptest.NewRequest("GET", "/", nil), account, "test profile", "https://app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return account.ID, credential.Token
}

func profilePNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, 640, 640))
	for y := range 640 {
		for x := range 640 {
			img.Set(x, y, color.NRGBA{R: uint8(x), G: uint8(y), B: 40, A: 255})
		}
	}
	var raw bytes.Buffer
	if err := png.Encode(&raw, img); err != nil {
		t.Fatal(err)
	}
	return raw.Bytes()
}

func avatarRequest(s *Server, method, path, bearer, content_type string, raw []byte, length int64) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.ContentLength = length
	req.Header.Set("Content-Type", content_type)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestAvatarOwnershipValidationAndOriginalPreservation(t *testing.T) {
	_, s := newTestServer(t)
	original := profilePNG(t)
	uploads := 0
	var asset_server *httptest.Server
	asset_server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/assets") {
			if r.Header.Get("Authorization") != "Bearer test-assets" {
				t.Error("missing asset credential")
			}
			if r.Method == "POST" {
				uploads++
				if r.URL.Query().Get("visibility") != "private" || r.URL.Query().Get("namespace") != "profile-avatars" {
					t.Error("upload was not private and scoped")
				}
				raw, _ := io.ReadAll(r.Body)
				if !bytes.Equal(raw, original) {
					t.Error("original bytes changed")
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"key": "profile-avatars/avatar-hash.png", "namespace": "profile-avatars", "visibility": "private", "url_expires": true, "renditions": []map[string]any{
				{"name": "w128", "width": 128, "height": 128, "content_type": "image/png", "url": asset_server.URL + "/profile-avatars/w128.png?signed=private"},
				{"name": "w64", "width": 64, "height": 64, "content_type": "image/png", "url": asset_server.URL + "/profile-avatars/w64.png?signed=private"},
				{"name": "original", "width": 640, "height": 640, "content_type": "image/png", "url": asset_server.URL + "/profile-avatars/original.png?signed=private"},
			}})
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("asset credential reached storage")
		}
		fmt.Fprint(w, r.URL.Path)
	}))
	defer asset_server.Close()
	var err error
	s.Avatars, err = avatar.New(asset_server.URL, "test-assets", "profile-avatars", asset_server.URL)
	if err != nil {
		t.Fatal(err)
	}
	account_id, bearer := profileCredential(t, s, "1")
	other_id, other_bearer := profileCredential(t, s, "2")
	upload := avatarRequest(s, "POST", "/v1/avatar?account="+other_id, bearer, "image/png", original, int64(len(original)))
	if upload.Code != 201 {
		t.Fatalf("upload: %d %s", upload.Code, upload.Body.String())
	}
	stored, _ := s.Store.AccountByID(context.Background(), account_id)
	other, _ := s.Store.AccountByID(context.Background(), other_id)
	if stored.AvatarWidth != 640 || stored.AvatarKey == "" || other.AvatarKey != "" || uploads != 1 {
		t.Fatal("wrong avatar ownership")
	}
	for _, test := range []struct {
		bearer string
		size   int
		status int
		path   string
	}{
		{"", 64, 401, ""}, {other_bearer, 64, 404, ""}, {bearer, 32, 200, "w64.png"}, {bearer, 96, 200, "w128.png"}, {bearer, 900, 200, "original.png"}, {bearer, 2000, 400, ""},
	} {
		resp := avatarRequest(s, "GET", fmt.Sprintf("/v1/avatar?size=%d&account=%s", test.size, account_id), test.bearer, "", nil, 0)
		if resp.Code != test.status {
			t.Fatalf("image status %d, want %d", resp.Code, test.status)
		}
		if test.status == 200 && (!strings.HasSuffix(resp.Body.String(), test.path) || resp.Header().Get("Location") != "" || !strings.Contains(resp.Header().Get("Cache-Control"), "no-store") || strings.Contains(resp.Body.String(), "signed")) {
			t.Fatalf("wrong/private image response: %s", resp.Body.String())
		}
	}
	who := avatarRequest(s, "GET", "/v1/whoami", bearer, "", nil, 0)
	if !strings.Contains(who.Body.String(), `"avatar"`) || !strings.Contains(who.Body.String(), `"avatar_upload_enabled":true`) || strings.Contains(who.Body.String(), "signed=") {
		t.Fatal("wrong profile description")
	}
	for _, method := range []string{"GET", "POST"} {
		if resp := avatarRequest(s, method, "/v1/tokens", bearer, "application/json", nil, 0); resp.Code != 403 {
			t.Fatal("profile credential gained token management")
		}
	}
	if resp := avatarRequest(s, "DELETE", "/v1/avatar", other_bearer, "", nil, 0); resp.Code != 204 {
		t.Fatal("remove other empty photo")
	}
	if stored, _ := s.Store.AccountByID(context.Background(), account_id); stored.AvatarKey == "" {
		t.Fatal("another account removed this avatar")
	}
	if resp := avatarRequest(s, "DELETE", "/v1/avatar", bearer, "", nil, 0); resp.Code != 204 {
		t.Fatal("remove failed")
	}
	if resp := avatarRequest(s, "GET", "/v1/avatar", bearer, "", nil, 0); resp.Code != 404 {
		t.Fatal("removed avatar still accessible")
	}
}

func TestAvatarRejectsLargeFakeAndDamagedImages(t *testing.T) {
	_, s := newTestServer(t)
	s.Avatars, _ = avatar.New("https://assets.example.com", "test", "profile-avatars", "https://storage.example.com")
	_, bearer := profileCredential(t, s, "1")
	large_pixels := append([]byte{}, profilePNG(t)...)
	binary.BigEndian.PutUint32(large_pixels[16:20], 8192)
	binary.BigEndian.PutUint32(large_pixels[20:24], 8192)
	binary.BigEndian.PutUint32(large_pixels[29:33], crc32.ChecksumIEEE(large_pixels[12:29]))
	for _, test := range []struct {
		name, content_type string
		raw                []byte
		length             int64
		status             int
	}{
		{"declared size", "image/png", nil, 10 << 30, 413},
		{"streamed size", "image/png", make([]byte, MAX_AVATAR_BYTES+1), -1, 413},
		{"zip", "application/zip", []byte("PK\x03\x04"), 4, 415},
		{"fake png", "image/png", []byte("PK\x03\x04"), 4, 415},
		{"pixels", "image/png", large_pixels, int64(len(large_pixels)), 413},
		{"truncated", "image/png", profilePNG(t)[:40], 40, 415},
	} {
		t.Run(test.name, func(t *testing.T) {
			resp := avatarRequest(s, "POST", "/v1/avatar", bearer, test.content_type, test.raw, test.length)
			if resp.Code != test.status {
				t.Fatalf("%d %s", resp.Code, resp.Body.String())
			}
		})
	}
	avatarRequest(s, "POST", "/v1/avatar", bearer, "image/png", []byte("bad"), 3)
	avatarRequest(s, "POST", "/v1/avatar", bearer, "image/png", []byte("bad"), 3)
	resp := avatarRequest(s, "POST", "/v1/avatar", bearer, "image/png", []byte("bad"), 3)
	if resp.Code != 429 {
		t.Fatalf("missing account throttle: %d", resp.Code)
	}
}

func TestAvatarCookieWritesRequireSameOrigin(t *testing.T) {
	_, s := newTestServer(t)
	account, _ := s.Store.SignIn(context.Background(), "github", "1", "reader")
	credential, _ := s.issue(httptest.NewRequest("GET", "/", nil), account, "browser", "")
	req := httptest.NewRequest("DELETE", "/v1/avatar", nil)
	req.AddCookie(&http.Cookie{Name: s.sessionName(), Value: credential.Token})
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("cross-origin cookie photo mutation accepted")
	}
}

func TestProviderAvatarPrioritySelectionAndFallback(t *testing.T) {
	_, s := newTestServer(t)
	account, err := s.Store.SignIn(context.Background(), "github", "1", "first")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Link(context.Background(), account.ID, "discord", "2", "second"); err != nil {
		t.Fatal(err)
	}
	s.Store.SetIdentityAvatar(context.Background(), "github", "1", "profile-avatars/github.png", 400, 400)
	s.Store.SetIdentityAvatar(context.Background(), "discord", "2", "profile-avatars/discord.png", 500, 500)
	identities, _ := s.Store.IdentitiesFor(context.Background(), account.ID)
	selected, _, _ := accountAvatars(account, identities)
	if selected == nil || selected.Source != "github" {
		t.Fatalf("first linked provider was not the default: %+v", selected)
	}
	credential, _ := s.issue(httptest.NewRequest("GET", "/", nil), account, "profile", "https://app.example.com")
	response := avatarRequest(s, "PUT", "/v1/avatar", credential.Token, "application/json", []byte(`{"source":"discord"}`), -1)
	if response.Code != 204 {
		t.Fatalf("select: %d %s", response.Code, response.Body.String())
	}
	account, _ = s.Store.AccountByID(context.Background(), account.ID)
	selected, _, _ = accountAvatars(account, identities)
	if selected == nil || selected.Source != "discord" {
		t.Fatalf("explicit provider was not selected: %+v", selected)
	}
	s.Store.SetIdentityAvatar(context.Background(), "discord", "2", "", 0, 0)
	identities, _ = s.Store.IdentitiesFor(context.Background(), account.ID)
	selected, _, _ = accountAvatars(account, identities)
	if selected == nil || selected.Source != "github" {
		t.Fatalf("missing selection did not fall back: %+v", selected)
	}
	response = avatarRequest(s, "GET", "/v1/whoami", credential.Token, "", nil, 0)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"source":"github"`) || strings.Contains(response.Body.String(), "profile-avatars/github.png") {
		t.Fatalf("whoami did not return a private source description: %s", response.Body.String())
	}
}
