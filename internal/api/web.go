package api

import (
	"embed"
	"html/template"
	"net/http"
)

// The page holds its token in the tab (sessionStorage) rather than in a
// cookie, and attaches it by hand to every request. Nothing here is an
// ambient credential, so there is nothing for another site to make this page
// do on a visitor's behalf. The one cookie in the whole flow is the Discord
// state cookie, which proves nothing but "this browser started a sign-in".

//go:embed web/index.html web/style.css web/callback.html
var webFiles embed.FS

var callbackTemplate = template.Must(template.ParseFS(webFiles, "web/callback.html"))

// callbackView is what the Discord callback page can say: a fresh token to
// stash and carry home, a completed link, or what went wrong.
type callbackView struct {
	Token  string
	Linked bool
	Error  string
}

func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	serveEmbedded(w, "web/index.html", "text/html; charset=utf-8")
}

func (s *Server) stylesheet(w http.ResponseWriter, r *http.Request) {
	serveEmbedded(w, "web/style.css", "text/css; charset=utf-8")
}

func (s *Server) callbackPage(w http.ResponseWriter, view callbackView) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := callbackTemplate.Execute(w, view); err != nil {
		s.logger().Error("web: render callback", "error", err)
	}
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
