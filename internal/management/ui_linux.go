package management

import (
	"embed"
	"net/http"
)

// Static files are part of the reviewed binary. No directory serving, remote
// dependencies or unauthenticated fallback is allowed.
//
//go:embed ui/index.html ui/app.js ui/app.css
var interfaceFiles embed.FS

func (h *httpService) serveUI(w http.ResponseWriter, r *http.Request, p Principal) bool {
	var path, media string
	switch r.URL.Path {
	case "/":
		path, media = "ui/index.html", "text/html; charset=utf-8"
	case "/ui/app.js":
		path, media = "ui/app.js", "text/javascript; charset=utf-8"
	case "/ui/app.css":
		path, media = "ui/app.css", "text/css; charset=utf-8"
	default:
		return false
	}
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		failHTTP(w, ErrInvalid)
		return true
	}
	if !oneOfRole(p, "owner", "operator", "viewer", "recovery") {
		failHTTP(w, ErrDenied)
		return true
	}
	raw, err := interfaceFiles.ReadFile(path)
	if err != nil {
		failHTTP(w, ErrUnavailable)
		return true
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
	return true
}
