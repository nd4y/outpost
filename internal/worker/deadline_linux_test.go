package worker

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type stalledBody struct {
	io.ReadCloser
	entered chan struct{}
}

func (b *stalledBody) Read(p []byte) (int, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	return b.ReadCloser.Read(p)
}

func TestWithdrawnRouteInterruptsAuthorizedIncompleteBody(t *testing.T) {
	f := newFixture(t)
	entered := make(chan struct{}, 1)
	server := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
			r.Body = &stalledBody{r.Body, entered}
			next.ServeHTTP(out, r)
		})
	})
	push, _ := f.rules()
	f.replicationConfig(t, 1, 1, push)
	start(t, f.nodes[1])
	wait(t, func() bool { f.nodes[1].mu.Lock(); defer f.nodes[1].mu.Unlock(); return f.nodes[1].active != nil })
	conn, e := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[0].cert}})
	must(t, e)
	defer conn.Close()
	must(t, conn.SetDeadline(time.Now().Add(8*time.Second)))
	id := storage.Hash([]byte("incomplete catalog"))
	j := push.Job(f.domain.Trust, id)
	_, e = fmt.Fprintf(conn, "PUT /v1/%s/generations/%s/catalog HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 8388608\r\nOutpost-Operation: %s\r\nOutpost-Mode: push\r\nOutpost-History: 1\r\nOutpost-Required-Revision: 1\r\n\r\n{", f.domain.Trust.Domain, id, j.Operation)
	must(t, e)
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("authorized body was not read")
	}
	f.replicationConfig(t, 1, 2)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.nodes[1].mu.Lock()
		active := f.nodes[1].active
		ready := active != nil && active.cfg.Revision == 2
		f.nodes[1].mu.Unlock()
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("configuration withdrawal waited for the unfinished request body")
}
