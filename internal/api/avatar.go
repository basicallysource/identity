package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/basicallysource/identity/internal/provider"
	"github.com/basicallysource/identity/internal/store"
	_ "golang.org/x/image/webp"
)

const MAX_AVATAR_BYTES = 5 << 20
const MAX_AVATAR_PIXELS = 16_000_000
const MAX_AVATAR_DIMENSION = 8192

var errAvatarDimensions = errors.New("image dimensions are too large")

type avatarBody struct {
	ID     string `json:"id"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Source string `json:"source"`
}

func describeAvatar(source, key string, width, height int) *avatarBody {
	if key == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(key))
	return &avatarBody{ID: hex.EncodeToString(sum[:8]), Width: width, Height: height, Source: source}
}

func accountAvatars(account store.Account, identities []store.Identity) (*avatarBody, *avatarBody, map[string]*avatarBody) {
	uploaded := describeAvatar("upload", account.AvatarKey, account.AvatarWidth, account.AvatarHeight)
	provider_avatars := map[string]*avatarBody{}
	for _, identity := range identities {
		source := identity.Provider
		if avatar := describeAvatar(source, identity.AvatarKey, identity.AvatarWidth, identity.AvatarHeight); avatar != nil && provider_avatars[source] == nil {
			provider_avatars[source] = avatar
		}
	}
	if account.AvatarSource == "upload" && uploaded != nil {
		return uploaded, uploaded, provider_avatars
	}
	if selected := provider_avatars[account.AvatarSource]; selected != nil {
		return selected, uploaded, provider_avatars
	}
	for _, identity := range identities {
		if avatar := provider_avatars[identity.Provider]; avatar != nil {
			return avatar, uploaded, provider_avatars
		}
	}
	return uploaded, uploaded, provider_avatars
}

func avatarImage(raw []byte, content_type string) (int, int, string, error) {
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || content_type != "image/"+format {
		return 0, 0, "", errors.New("unsupported image")
	}
	if config.Width < 1 || config.Height < 1 || config.Width > MAX_AVATAR_DIMENSION || config.Height > MAX_AVATAR_DIMENSION || int64(config.Width)*int64(config.Height) > MAX_AVATAR_PIXELS {
		return 0, 0, "", errAvatarDimensions
	}
	if _, _, err := image.Decode(bytes.NewReader(raw)); err != nil {
		return 0, 0, "", errors.New("damaged image")
	}
	extension := "." + format
	if format == "jpeg" {
		extension = ".jpg"
	}
	return config.Width, config.Height, extension, nil
}

func (s *Server) saveProviderAvatar(ctx context.Context, provider_name string, user provider.User) {
	if s.Avatars == nil || user.AvatarURL == "" {
		return
	}
	s.avatar_mu.Lock()
	defer s.avatar_mu.Unlock()
	if s.Store.HasIdentityAvatar(ctx, provider_name, user.ID) {
		return
	}
	raw, content_type, err := s.Avatars.ProviderImage(ctx, provider_name, user.ID, user.AvatarURL, MAX_AVATAR_BYTES)
	if err != nil {
		s.logger().Warn("provider profile photo unavailable", "provider", provider_name, "error", err)
		return
	}
	width, height, extension, err := avatarImage(raw, content_type)
	if err != nil {
		s.logger().Warn("provider profile photo rejected", "provider", provider_name, "error", err)
		return
	}
	key, err := s.Avatars.Upload(ctx, raw, content_type, extension)
	if err != nil || s.Store.SetIdentityAvatar(ctx, provider_name, user.ID, key, width, height) != nil {
		s.logger().Warn("provider profile photo could not be saved", "provider", provider_name)
	}
}

func (s *Server) uploadAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, 401, "sign in required")
		return
	}
	if s.Avatars == nil {
		writeError(w, 503, "profile photos are not configured")
		return
	}
	if r.ContentLength > MAX_AVATAR_BYTES {
		writeError(w, 413, "choose an image no larger than 5 MiB")
		return
	}
	content_type, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if content_type != "image/jpeg" && content_type != "image/png" && content_type != "image/webp" {
		writeError(w, 415, "choose a JPEG, PNG or WebP image")
		return
	}
	if !s.avatar_mu.TryLock() {
		writeError(w, 503, "another photo is processing; try again shortly")
		return
	}
	defer s.avatar_mu.Unlock()
	if !s.avatar_throttle.allow(account.ID, s.now()) {
		w.Header().Set("Retry-After", "3600")
		writeError(w, 429, "profile photos can be changed six times per hour")
		return
	}
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(30 * time.Second))
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MAX_AVATAR_BYTES))
	if err != nil {
		writeError(w, 413, "choose an image no larger than 5 MiB")
		return
	}
	width, height, extension, err := avatarImage(raw, content_type)
	if errors.Is(err, errAvatarDimensions) {
		writeError(w, 413, "image must be at most 16 megapixels and 8192 pixels per side")
		return
	}
	if err != nil {
		writeError(w, 415, "this file is not a supported image")
		return
	}
	key, err := s.Avatars.Upload(r.Context(), raw, content_type, extension)
	if err != nil {
		writeError(w, 502, "could not store the profile photo")
		return
	}
	if err := s.Store.SetAvatar(r.Context(), account.ID, key, width, height); err != nil {
		writeError(w, 500, "could not save the profile photo")
		return
	}
	writeJSON(w, 201, describeAvatar("upload", key, width, height))
}

func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, 401, "sign in required")
		return
	}
	identities, err := s.Store.IdentitiesFor(r.Context(), account.ID)
	if err != nil || s.Avatars == nil {
		writeError(w, 404, "no profile photo")
		return
	}
	selected, uploaded, provider_avatars := accountAvatars(account, identities)
	if source := r.URL.Query().Get("source"); source != "" {
		if source == "upload" {
			selected = uploaded
		} else {
			selected = provider_avatars[source]
		}
	}
	if selected == nil {
		writeError(w, 404, "no profile photo")
		return
	}
	size := 128
	if value := r.URL.Query().Get("size"); value != "" {
		size, err = strconv.Atoi(value)
		if err != nil || size < 16 || size > 1024 {
			writeError(w, 400, "size must be between 16 and 1024 pixels")
			return
		}
	}
	key := account.AvatarKey
	if selected.Source != "upload" {
		for _, identity := range identities {
			if selected.Source == identity.Provider {
				key = identity.AvatarKey
				break
			}
		}
	}
	resp, err := s.Avatars.Image(r.Context(), key, size)
	if err != nil {
		writeError(w, 502, "profile photo unavailable")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if r.Method != "HEAD" {
		io.Copy(w, resp.Body)
	}
}

func (s *Server) selectAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, 401, "sign in required")
		return
	}
	var body struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil || body.Source == "" {
		writeError(w, 400, `send {"source":"github"}`)
		return
	}
	if err := s.Store.SelectAvatar(r.Context(), account.ID, body.Source); err != nil {
		writeError(w, 400, "choose one of your available profile photos")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeAvatar(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, 401, "sign in required")
		return
	}
	if err := s.Store.SetAvatar(r.Context(), account.ID, "", 0, 0); err != nil {
		writeError(w, 500, "could not remove the profile photo")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
