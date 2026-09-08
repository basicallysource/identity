package api

import (
	"bytes"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/basicallysource/identity/internal/store"
	_ "golang.org/x/image/webp"
)

const MAX_AVATAR_BYTES = 5 << 20
const MAX_AVATAR_PIXELS = 16_000_000
const MAX_AVATAR_DIMENSION = 8192

type avatarBody struct {
	ID     string `json:"id"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

func describeAvatar(account store.Account) *avatarBody {
	if account.AvatarKey == "" {
		return nil
	}
	return &avatarBody{ID: account.AvatarKey, Width: account.AvatarWidth, Height: account.AvatarHeight}
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
	config, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || content_type != "image/"+format {
		writeError(w, 415, "this file is not a supported image")
		return
	}
	if config.Width < 1 || config.Height < 1 || config.Width > MAX_AVATAR_DIMENSION || config.Height > MAX_AVATAR_DIMENSION || int64(config.Width)*int64(config.Height) > MAX_AVATAR_PIXELS {
		writeError(w, 413, "image must be at most 16 megapixels and 8192 pixels per side")
		return
	}
	if _, _, err := image.Decode(bytes.NewReader(raw)); err != nil {
		writeError(w, 415, "this image is damaged or incomplete")
		return
	}
	extension := "." + format
	if format == "jpeg" {
		extension = ".jpg"
	}
	key, err := s.Avatars.Upload(r.Context(), raw, content_type, extension)
	if err != nil {
		writeError(w, 502, "could not store the profile photo")
		return
	}
	if err := s.Store.SetAvatar(r.Context(), account.ID, key, config.Width, config.Height); err != nil {
		writeError(w, 500, "could not save the profile photo")
		return
	}
	writeJSON(w, 201, avatarBody{ID: key, Width: config.Width, Height: config.Height})
}

func (s *Server) avatar(w http.ResponseWriter, r *http.Request) {
	account, _, err := s.authenticate(r)
	if err != nil {
		writeError(w, 401, "sign in required")
		return
	}
	if account.AvatarKey == "" || s.Avatars == nil {
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
	resp, err := s.Avatars.Image(r.Context(), account.AvatarKey, size)
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
