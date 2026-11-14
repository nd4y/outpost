package managementservice

import (
	"net"
	"net/http"
	"sync"
)

// Closing admission before waiting prevents Add/Wait races. TLS handshakes
// are handled by http.Server; this gate joins actual application handlers.
type drainingHandler struct {
	handler http.Handler
	mu      sync.Mutex
	closing bool
	active  sync.WaitGroup
}

func (h *drainingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	if h.closing {
		h.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	h.active.Add(1)
	h.mu.Unlock()
	defer h.active.Done()
	h.handler.ServeHTTP(w, r)
}
func (h *drainingHandler) drain() { h.mu.Lock(); h.closing = true; h.mu.Unlock() }

// Bound live sockets before TLS allocates per-connection state. Overload does
// not consume the separate command lane or create an unbounded wait queue.
type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			_ = c.Close()
		}
	}
}
