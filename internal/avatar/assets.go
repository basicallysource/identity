package avatar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var NAMESPACE_PATTERN = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var KEY_PATTERN = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*/[A-Za-z0-9._-]+$`)
var DISCORD_DEFAULT_AVATAR_PATTERN = regexp.MustCompile(`^/embed/avatars/[0-5]\.png$`)

type Assets struct {
	base_url, token, namespace, storage_origin string
	client                                     *http.Client
}

type Rendition struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	URL         string `json:"url"`
}

type Manifest struct {
	Key        string      `json:"key"`
	Namespace  string      `json:"namespace"`
	Visibility string      `json:"visibility"`
	URLExpires bool        `json:"url_expires"`
	Renditions []Rendition `json:"renditions"`
}

func New(base_url, token, namespace, storage_origin string) (*Assets, error) {
	for _, value := range []string{base_url, storage_origin} {
		u, err := url.Parse(value)
		if err != nil || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
			return nil, errors.New("avatar services require HTTPS origins")
		}
	}
	if token == "" || !NAMESPACE_PATTERN.MatchString(namespace) {
		return nil, errors.New("avatar storage credentials and namespace are required")
	}
	return &Assets{base_url: base_url, token: token, namespace: namespace, storage_origin: storage_origin, client: &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (a *Assets) manifest(ctx context.Context, method, path, content_type string, body io.Reader) (Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, method, a.base_url+path, body)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", content_type)
	resp, err := a.client.Do(req)
	if err != nil {
		return Manifest{}, errors.New("avatar storage unavailable")
	}
	defer resp.Body.Close()
	var result Manifest
	if (resp.StatusCode != 200 && resp.StatusCode != 201) || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&result) != nil || result.Namespace != a.namespace || result.Visibility != "private" || !result.URLExpires || !KEY_PATTERN.MatchString(result.Key) || !strings.HasPrefix(result.Key, a.namespace+"/") {
		return Manifest{}, errors.New("invalid private avatar asset")
	}
	return result, nil
}

func (a *Assets) Upload(ctx context.Context, raw []byte, content_type, extension string) (string, error) {
	query := url.Values{"namespace": {a.namespace}, "visibility": {"private"}, "filename": {"avatar" + extension}}
	result, err := a.manifest(ctx, "POST", "/v1/assets?"+query.Encode(), content_type, bytes.NewReader(raw))
	return result.Key, err
}

func (a *Assets) ProviderImage(ctx context.Context, provider, provider_id, source_url string, max_bytes int64) ([]byte, string, error) {
	u, err := url.Parse(source_url)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || !validProviderURL(provider, provider_id, u) {
		return nil, "", errors.New("invalid provider image URL")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", source_url, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", errors.New("provider image unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > max_bytes {
		return nil, "", errors.New("provider image unavailable")
	}
	content_type, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if content_type != "image/jpeg" && content_type != "image/png" && content_type != "image/webp" {
		return nil, "", errors.New("unsupported provider image")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, max_bytes+1))
	if err != nil || int64(len(raw)) > max_bytes {
		return nil, "", errors.New("provider image is too large")
	}
	return raw, content_type, nil
}

func validProviderURL(provider, provider_id string, u *url.URL) bool {
	switch provider {
	case "github":
		return u.Host == "avatars.githubusercontent.com" && u.Path == "/u/"+provider_id
	case "discord":
		return u.Host == "cdn.discordapp.com" && ((strings.HasPrefix(u.Path, "/avatars/"+provider_id+"/") && strings.HasSuffix(u.Path, ".png")) || DISCORD_DEFAULT_AVATAR_PATTERN.MatchString(u.Path))
	default:
		return false
	}
}

func (a *Assets) Image(ctx context.Context, key string, size int) (*http.Response, error) {
	if !KEY_PATTERN.MatchString(key) || !strings.HasPrefix(key, a.namespace+"/") {
		return nil, errors.New("invalid avatar")
	}
	manifest, err := a.manifest(ctx, "GET", "/v1/assets/"+key, "", nil)
	if err != nil || manifest.Key != key {
		return nil, errors.New("avatar unavailable")
	}
	var selected Rendition
	selected_size := 0
	for _, candidate := range manifest.Renditions {
		if candidate.ContentType != "image/jpeg" && candidate.ContentType != "image/png" && candidate.ContentType != "image/webp" {
			continue
		}
		pixels := min(candidate.Width, candidate.Height)
		if pixels < 1 {
			continue
		}
		if selected_size == 0 || (pixels >= size && (selected_size < size || pixels < selected_size)) || (pixels < size && selected_size < size && pixels > selected_size) {
			selected, selected_size = candidate, pixels
		}
	}
	u, err := url.Parse(selected.URL)
	if err != nil || selected_size == 0 || u.User != nil || u.Fragment != "" || u.Scheme+"://"+u.Host != a.storage_origin || !KEY_PATTERN.MatchString(strings.TrimPrefix(u.Path, "/")) || !strings.HasPrefix(u.Path, "/"+a.namespace+"/") {
		return nil, errors.New("invalid avatar storage URL")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", selected.URL, nil)
	if err != nil {
		return nil, errors.New("invalid avatar request")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, errors.New("avatar storage unavailable")
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("avatar storage returned %d", resp.StatusCode)
	}
	resp.Header.Set("Content-Type", selected.ContentType)
	return resp, nil
}
