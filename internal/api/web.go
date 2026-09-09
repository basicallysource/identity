package api

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The page is html/template over web/*.html, styled by web/style.css, which
// Tailwind builds from web/input.css and the class names in the templates:
//
//	cd internal/api/web && npm ci && npm run build
//
// The output is committed, so a checkout builds with Go alone; CI rebuilds
// it and fails if it differs. htmx is the vendored web/htmx.min.js.

//go:embed web/*.html web/style.css web/htmx.min.js
var webFiles embed.FS

// Static files are served under a content hash, /static/<hash>/<name>, and
// told to be cached forever. A changed file is a new URL, so no cache
// between here and the browser (a CDN in front rewrites Cache-Control
// on .css, and did) can ever serve a stale one against a new page.
var assets = map[string]string{}

func init() {
	for _, name := range []string{"style.css", "htmx.min.js"} {
		body, err := webFiles.ReadFile("web/" + name)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(body)
		assets[name] = hex.EncodeToString(sum[:8])
	}
}

func assetURL(name string) string { return "/static/" + assets[name] + "/" + name }

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"asset": assetURL,
	"date": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Local().Format("2 Jan 2006")
	},
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			return strings.TrimSuffix(d.Round(time.Minute).String(), "0s") + " ago"
		case d < 48*time.Hour:
			return d.Round(time.Hour).String() + " ago"
		default:
			return t.Local().Format("2 Jan 2006")
		}
	},
	"has": func(list []string, item string) bool {
		for _, x := range list {
			if x == item {
				return true
			}
		}
		return false
	},
	"hasProvider": func(identities []identityBody, provider string) bool {
		for _, i := range identities {
			if i.Provider == provider {
				return true
			}
		}
		return false
	},
	"plural": func(n int, word string) string {
		if n == 1 {
			return "1 " + word
		}
		return strconv.Itoa(n) + " " + word + "s"
	},
}).ParseFS(webFiles, "web/*.html"))

// callbackView is what the Discord callback can say: a completed link, or
// what went wrong.
type callbackView struct {
	Linked bool
	Error  string
}

// render executes one named template into the response. A template that
// fails to execute is a bug, and it is answered as one rather than as half
// a page.
func (s *Server) render(w http.ResponseWriter, status int, name string, data view) {
	var out bytes.Buffer
	if err := templates.ExecuteTemplate(&out, name, data); err != nil {
		s.logger().Error("web: render "+name, "error", err)
		http.Error(w, "could not render the page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(out.Bytes())
}

// static serves one embedded file under its content hash. A URL with any
// other hash is a stale reference and gets 404, never a wrong file.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	if hash, ok := assets[name]; !ok || hash != r.PathValue("hash") {
		http.NotFound(w, r)
		return
	}
	body, _ := webFiles.ReadFile("web/" + name)
	contentType := "text/css; charset=utf-8"
	if strings.HasSuffix(name, ".js") {
		contentType = "text/javascript; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(body)
}

// callbackPage answers the Discord callback: a link sends the browser to
// the page, a failure is the sign-in view with the reason.
func (s *Server) callbackPage(w http.ResponseWriter, view_ callbackView) {
	if view_.Linked {
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "page", view{Providers: s.providerFlags(), Error: view_.Error})
}
