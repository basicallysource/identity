package api

import (
	"bytes"
	"embed"
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

var templates = template.Must(template.New("").Funcs(template.FuncMap{
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

func (s *Server) stylesheet(w http.ResponseWriter, r *http.Request) {
	serveEmbedded(w, "web/style.css", "text/css; charset=utf-8")
}

func (s *Server) script(w http.ResponseWriter, r *http.Request) {
	serveEmbedded(w, "web/htmx.min.js", "text/javascript; charset=utf-8")
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

func serveEmbedded(w http.ResponseWriter, name, contentType string) {
	body, err := webFiles.ReadFile(name)
	if err != nil {
		http.Error(w, "missing page", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(body)
}
