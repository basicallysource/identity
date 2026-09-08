package avatar

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrivateManifestAndStorageBoundary(t *testing.T) {
	for _, mode := range []string{"public", "permanent URL", "wrong key", "other namespace", "foreign origin", "redirect", "HTML"} {
		t.Run(mode, func(t *testing.T) {
			var service *httptest.Server
			service = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/profile-avatars/image.png" {
					if mode != "redirect" {
						t.Error("untrusted image reached storage")
					}
					http.Redirect(w, r, "https://unexpected.example/", 302)
					return
				}
				manifest := Manifest{Key: "profile-avatars/image.png", Namespace: "profile-avatars", Visibility: "private", URLExpires: true, Renditions: []Rendition{{Name: "original", Width: 100, Height: 100, ContentType: "image/png", URL: service.URL + "/profile-avatars/image.png?signed=1"}}}
				switch mode {
				case "public":
					manifest.Visibility = "public"
				case "permanent URL":
					manifest.URLExpires = false
				case "wrong key":
					manifest.Key = "profile-avatars/other.png"
				case "other namespace":
					manifest.Namespace = "other"
				case "foreign origin":
					manifest.Renditions[0].URL = "https://unexpected.example/image.png"
				case "HTML":
					manifest.Renditions[0].ContentType = "text/html"
				}
				json.NewEncoder(w).Encode(manifest)
			}))
			defer service.Close()
			assets, err := New(service.URL, "test", "profile-avatars", service.URL)
			if err != nil {
				t.Fatal(err)
			}
			if response, err := assets.Image(context.Background(), "profile-avatars/image.png", 64); err == nil {
				response.Body.Close()
				t.Fatal("unsafe private image accepted")
			}
		})
	}
}
