package management

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestManagementUIUsesAuthenticatedExactRoutesAndRestrictiveBrowserHeaders(t *testing.T) {
	h := newHTTPFixture(t)
	h.f.enroll(t)
	for path, media := range map[string]string{"/": "text/html", "/ui/app.js": "text/javascript", "/ui/app.css": "text/css"} {
		for _, client := range []*http.Client{h.owner, h.viewer} {
			res, e := client.Get(h.server.URL + path)
			must(t, e)
			raw, e := io.ReadAll(io.LimitReader(res.Body, 256<<10))
			res.Body.Close()
			must(t, e)
			if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), media) || len(raw) == 0 || len(raw) >= 256<<10 {
				t.Fatal("embedded resource unavailable", path, res.StatusCode, len(raw))
			}
			csp := res.Header.Get("Content-Security-Policy")
			for _, rule := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"} {
				if !strings.Contains(csp, rule) {
					t.Fatal("browser boundary missing", path, rule)
				}
			}
			if strings.Contains(csp, "unsafe-") || res.Header.Get("Cache-Control") != "no-store" || res.Header.Get("Referrer-Policy") != "no-referrer" || res.Header.Get("X-Content-Type-Options") != "nosniff" || res.Header.Get("Cross-Origin-Resource-Policy") != "same-origin" {
				t.Fatal("private browser response weakened", path)
			}
		}
		for _, client := range []*http.Client{h.unknown, h.node} {
			status, _ := h.request(t, client, "GET", path, nil)
			if status != 403 {
				t.Fatal("non-operator static access", path, status)
			}
		}
		for _, suffix := range []string{"?cache=1", "?"} {
			status, _ := h.request(t, h.owner, "GET", path+suffix, nil)
			if status != 400 {
				t.Fatal("static alias accepted", path+suffix, status)
			}
		}
		status, _ := h.request(t, h.owner, "POST", path, map[string]string{})
		if status != 400 {
			t.Fatal("static mutation accepted", path, status)
		}
	}
	for _, path := range []string{"/index.html", "/ui/", "/ui/%61pp.js", "/ui/../app.js", "/ui/not-found.js"} {
		status, _ := h.request(t, h.owner, "GET", path, nil)
		if status == 200 || status >= 300 && status < 400 {
			t.Fatal("static directory/alias/redirect exposed", path, status)
		}
	}
}
