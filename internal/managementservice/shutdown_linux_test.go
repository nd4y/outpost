package managementservice

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestManagementServiceDrainingJoinsAdmittedHandlersAndRejectsNewOnes(t *testing.T) {
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := &drainingHandler{handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})}
	go func() { h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil)); close(returned) }()
	<-entered
	h.drain()
	joined := make(chan struct{})
	go func() { h.active.Wait(); close(joined) }()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("new work admitted while draining")
	}
	select {
	case <-joined:
		t.Fatal("returned before active handler")
	default:
	}
	close(release)
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("active handler not joined")
	}
	<-returned
}

func TestManagementServiceStopClosesSilentTLSWithoutReportingGraceDeadline(t *testing.T) {
	f := newFixture(t)
	s, e := Open(context.Background(), f.p, true)
	must(t, e)
	defer s.Close()
	cancel, done := start(t, s, f.client)
	defer cancel()
	conn, e := net.DialTimeout("tcp", f.p.Listen, time.Second)
	must(t, e)
	defer conn.Close()
	// An incomplete TLS record cannot become an admitted application request.
	_, e = conn.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x20})
	must(t, e)
	stop(t, cancel, done)
	must(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
	var b [1]byte
	if _, e = conn.Read(b[:]); e == nil {
		t.Fatal("silent client remained open")
	}
}
