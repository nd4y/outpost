// Package teststore is a synthetic HTTPS protocol fixture, not a storage server.
// Payloads are kept under the caller's admitted temporary data volume.
package teststore

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type Login struct{ Secret, Token string }
type Hook func(http.ResponseWriter, *http.Request, string, string, []byte) bool
type Options struct {
	Kind, Namespace, Directory, Region string
	MaxObject                          int
	Logins                             map[string]Login
	Delay                              time.Duration
	Before                             Hook
	AfterWrite                         Hook
	MoveOnly                           bool
	IgnoreMoveOverwrite                bool
}
type Event struct {
	Actor, Key string
	Bytes      int
	Start, End time.Time
}
type Snapshot struct {
	Events      []Event
	Writes      map[string]int
	Requests    int
	PeakWorkers int
}
type Server struct {
	HTTP     *httptest.Server
	Roots    *x509.CertPool
	Options  Options
	mu       sync.Mutex
	events   []Event
	writes   map[string]int
	requests int
	active   map[string]int
	peak     int
}

func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func hmac256(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(s))
	return h.Sum(nil)
}
func Root(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if required := os.Getenv("OUTPOST_TEST_ROOT"); required != "" {
		rel, e := filepath.Rel(required, dir)
		if e != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			t.Fatal("test data outside admitted volume")
		}
	}
	return dir
}
func New(t *testing.T, o Options) *Server {
	t.Helper()
	if o.Directory == "" {
		o.Directory = Root(t)
	}
	if o.MaxObject == 0 {
		o.MaxObject = 64 << 10
	}
	if o.Region == "" {
		o.Region = "test-region"
	}
	if o.Logins == nil {
		o.Logins = map[string]Login{"test-worker": {Secret: "ephemeral-test-secret"}}
	}
	s := &Server{Options: o, writes: map[string]int{}, active: map[string]int{}}
	s.HTTP = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	s.Roots = x509.NewCertPool()
	s.Roots.AddCert(s.HTTP.Certificate())
	t.Cleanup(s.HTTP.Close)
	return s
}
func (s *Server) Endpoint() string { return s.HTTP.URL + "/objects" }
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]int{}
	for k, v := range s.writes {
		m[k] = v
	}
	return Snapshot{append([]Event(nil), s.events...), m, s.requests, s.peak}
}
func (s *Server) Path(key string) string {
	return filepath.Join(s.Options.Directory, s.Options.Namespace+"-"+key)
}
func (s *Server) actor(r *http.Request, body []byte) (string, bool) {
	if s.Options.Kind == "webdav" {
		actor, secret, ok := r.BasicAuth()
		want, found := s.Options.Logins[actor]
		return actor, ok && found && secret == want.Secret
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
		return "", false
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return "", false
		}
		fields[kv[0]] = kv[1]
	}
	credential := strings.Split(fields["Credential"], "/")
	if len(credential) != 5 || credential[2] != s.Options.Region || credential[3] != "s3" || credential[4] != "aws4_request" {
		return "", false
	}
	actor := credential[0]
	login, ok := s.Options.Logins[actor]
	if !ok || r.Header.Get("X-Amz-Security-Token") != login.Token {
		return "", false
	}
	stamp := r.Header.Get("X-Amz-Date")
	date, e := time.Parse("20060102T150405Z", stamp)
	if e != nil || time.Since(date) > 5*time.Minute || time.Until(date) > 5*time.Minute || credential[1] != date.Format("20060102") || r.Header.Get("X-Amz-Content-Sha256") != hash(body) {
		return "", false
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	headers := ""
	for _, name := range signed {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		} else if name == "content-length" {
			// net/http parses this framing field separately from ordinary headers.
			value = strconv.FormatInt(r.ContentLength, 10)
		}
		headers += name + ":" + strings.Join(strings.Fields(value), " ") + "\n"
	}
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + r.URL.RawQuery + "\n" + headers + "\n" + fields["SignedHeaders"] + "\n" + hash(body)
	scope := strings.Join(credential[1:], "/")
	message := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hash([]byte(canonical))
	key := hmac256([]byte("AWS4"+login.Secret), credential[1])
	for _, part := range credential[2:] {
		key = hmac256(key, part)
	}
	signature, e := hex.DecodeString(fields["Signature"])
	return actor, e == nil && hmac.Equal(signature, hmac256(key, message))
}
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests++
	s.mu.Unlock()
	query := r.URL.RawQuery
	archive := s.Options.Kind == "s3" && r.Method == http.MethodPost && query == "restore="
	if ((r.Method == http.MethodPost || query != "") && !archive) || !strings.HasPrefix(r.URL.Path, "/objects/"+s.Options.Namespace+"-") {
		w.WriteHeader(403)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/objects/")
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			w.WriteHeader(400)
			return
		}
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, int64(s.Options.MaxObject)+1))
	if e != nil {
		w.WriteHeader(400)
		return
	}
	if len(body) > s.Options.MaxObject {
		w.WriteHeader(413)
		return
	}
	actor, ok := s.actor(r, body)
	if !ok {
		w.WriteHeader(403)
		return
	}
	key := strings.TrimPrefix(name, s.Options.Namespace+"-")
	if s.Options.Before != nil && s.Options.Before(w, r, actor, key, body) {
		return
	}
	target := filepath.Join(s.Options.Directory, name)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		data, e := os.ReadFile(target)
		if os.IsNotExist(e) {
			w.WriteHeader(404)
			return
		}
		if e != nil {
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("ETag", `"`+hash(data)+`"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case http.MethodPut:
		staging := strings.HasPrefix(key, "attempt-") || strings.HasPrefix(key, "probe-stage-")
		if s.Options.MoveOnly && (!staging || r.Header.Get("If-None-Match") != "") ||
			!s.Options.MoveOnly && r.Header.Get("If-None-Match") != "*" {
			w.WriteHeader(400)
			return
		}
		start := time.Now()
		part := strings.HasPrefix(key, "part-") || s.Options.MoveOnly && staging && len(body) > 4096
		if part {
			s.mu.Lock()
			s.active[actor]++
			if len(s.active) > s.peak {
				s.peak = len(s.active)
			}
			s.mu.Unlock()
			defer func() {
				s.mu.Lock()
				s.active[actor]--
				if s.active[actor] == 0 {
					delete(s.active, actor)
				}
				s.mu.Unlock()
			}()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(s.Options.Delay):
			}
		}
		temp, e := os.CreateTemp(s.Options.Directory, "pending-")
		if e != nil {
			w.WriteHeader(507)
			return
		}
		defer os.Remove(temp.Name())
		_, e = temp.Write(body)
		if e == nil {
			e = temp.Sync()
		}
		closeErr := temp.Close()
		if e != nil || closeErr != nil {
			w.WriteHeader(507)
			return
		}
		if s.Options.MoveOnly {
			e = os.Rename(temp.Name(), target)
		} else {
			e = os.Link(temp.Name(), target)
		}
		if os.IsExist(e) {
			w.WriteHeader(412)
			return
		} else if e != nil {
			w.WriteHeader(500)
			return
		}
		dir, e := os.Open(s.Options.Directory)
		if e != nil {
			w.WriteHeader(500)
			return
		}
		e = dir.Sync()
		dir.Close()
		if e != nil {
			w.WriteHeader(500)
			return
		}
		s.mu.Lock()
		s.writes[key]++
		if part {
			s.events = append(s.events, Event{actor, key, len(body), start, time.Now()})
		}
		s.mu.Unlock()
		if s.Options.AfterWrite != nil && s.Options.AfterWrite(w, r, actor, key, body) {
			return
		}
		w.WriteHeader(201)
	case "MOVE":
		s.serveMove(w, r, actor, key, target)
	default:
		w.WriteHeader(405)
	}
}

func (s *Server) serveMove(w http.ResponseWriter, r *http.Request, actor, key, source string) {
	if !s.Options.MoveOnly || s.Options.Kind != "webdav" || r.Header.Get("Overwrite") != "F" ||
		!strings.HasPrefix(key, "attempt-") && !strings.HasPrefix(key, "probe-stage-") {
		w.WriteHeader(405)
		return
	}
	prefix := "/objects/" + s.Options.Namespace + "-"
	destination, e := url.Parse(r.Header.Get("Destination"))
	if e != nil || destination.Scheme != "https" || destination.Host != r.Host || destination.User != nil || destination.RawQuery != "" || destination.Fragment != "" || !strings.HasPrefix(destination.Path, prefix) {
		w.WriteHeader(403)
		return
	}
	name := strings.TrimPrefix(destination.Path, prefix)
	if name == "" || strings.HasPrefix(name, "attempt-") || strings.HasPrefix(name, "probe-stage-") {
		w.WriteHeader(400)
		return
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			w.WriteHeader(400)
			return
		}
	}
	final := s.Path(name)
	s.mu.Lock()
	_, present := os.Lstat(final)
	if present == nil && !s.Options.IgnoreMoveOverwrite {
		s.mu.Unlock()
		w.WriteHeader(412)
		return
	}
	e = os.Rename(source, final)
	if e == nil {
		s.writes[name]++
	}
	s.mu.Unlock()
	if os.IsNotExist(e) {
		w.WriteHeader(404)
		return
	}
	if e != nil {
		w.WriteHeader(500)
		return
	}
	dir, e := os.Open(s.Options.Directory)
	if e == nil {
		e = dir.Sync()
		dir.Close()
	}
	if e != nil {
		w.WriteHeader(500)
		return
	}
	if s.Options.AfterWrite != nil && s.Options.AfterWrite(w, r, actor, name, nil) {
		return
	}
	w.WriteHeader(201)
}
func (s *Server) String() string { return fmt.Sprintf("synthetic %s endpoint", s.Options.Kind) }
