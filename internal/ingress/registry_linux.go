package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const RegistryFormat = "outpost-ingress-registry-1"

type RegistryOptions struct {
	Directory   string
	Authority   []byte
	Owner       ed25519.PublicKey
	Replica     *generation.Replica
	Certificate tls.Certificate
	Roots       *x509.CertPool
	Limits      peer.Limits
	Initialize  bool
	// Prefix is relative to the caller's shared capacity ledger.
	Admission    func(prefix string) statefile.Admission
	RemoveObject func(context.Context, string, int64) error
}
type registryState struct {
	Format       string          `json:"format"`
	Authority    string          `json:"authority"`
	Intent       json.RawMessage `json:"intent,omitempty"`
	ObservedUnix int64           `json:"observedUnix"`
}
type Registry struct {
	mu        sync.Mutex
	options   RegistryOptions
	authority Authority
	store     *statefile.Store
	lease     *os.File
	state     registryState
	session   *Session
	handler   http.Handler
	leaf      *x509.Certificate
	poisoned  bool
	gate      chan struct{}
	Fault     func(string) error
}

func (g *Registry) point(name string) error {
	if g.Fault != nil {
		return g.Fault(name)
	}
	return nil
}
func (g *Registry) admission(prefix string) statefile.Admission {
	if g.options.Admission == nil {
		return nil
	}
	return g.options.Admission(prefix)
}
func (g *Registry) save() error {
	raw, e := json.Marshal(g.state)
	if e != nil {
		return e
	}
	e = g.store.Write("registry.json", raw)
	if e != nil {
		g.poisoned = true
	}
	return e
}
func OpenRegistry(ctx context.Context, o RegistryOptions) (*Registry, error) {
	a, e := VerifyAuthority(o.Authority, o.Owner, time.Now())
	if e != nil {
		return nil, e
	}
	if !filepath.IsAbs(o.Directory) || filepath.Clean(o.Directory) != o.Directory || o.Replica == nil || !limitsOK(o.Limits) {
		return nil, ErrDenied
	}
	x, _ := json.Marshal(a.Trust)
	y, _ := json.Marshal(o.Replica.Trust())
	if !bytes.Equal(x, y) {
		return nil, ErrDenied
	}
	if _, e = peer.AuthenticatedServerTLS(o.Certificate, o.Roots, a.Ingress); e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(o.Certificate.Certificate[0])
	if e != nil {
		return nil, e
	}
	if o.Initialize {
		if e = os.Mkdir(o.Directory, 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return nil, e
		}
	}
	i, e := os.Lstat(o.Directory)
	if e != nil {
		return nil, e
	}
	if !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	lease, e := os.OpenFile(filepath.Join(o.Directory, ".registry-lock"), os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	i, e = lease.Stat()
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm()&0077 != 0 {
		lease.Close()
		return nil, ErrDenied
	}
	if e = unix.Flock(int(lease.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		lease.Close()
		return nil, ErrConflict
	}
	o.Authority = bytes.Clone(o.Authority)
	o.Owner = bytes.Clone(o.Owner)
	g := &Registry{options: o, authority: a, leaf: leaf, lease: lease, gate: make(chan struct{}, 1)}
	fail := func(e error) (*Registry, error) { g.Close(); return nil, e }
	g.store, e = statefile.Open(filepath.Join(o.Directory, "state"), 2*MaxDocument, o.Initialize)
	if e != nil {
		return fail(e)
	}
	g.store.Admit = g.admission("state")
	raw, e := g.store.Read("registry.json")
	if errors.Is(e, os.ErrNotExist) && o.Initialize {
		g.state = registryState{Format: RegistryFormat, Authority: storage.Hash(o.Authority), ObservedUnix: time.Now().Unix()}
		if e = g.save(); e != nil {
			return fail(e)
		}
	} else if e != nil {
		return fail(e)
	} else {
		if storage.Decode(raw, &g.state, 2*MaxDocument) != nil {
			return fail(ErrConflict)
		}
		canonical, _ := json.Marshal(g.state)
		if !bytes.Equal(raw, canonical) || g.state.Format != RegistryFormat || g.state.Authority != storage.Hash(o.Authority) || g.state.ObservedUnix < 1 || g.state.ObservedUnix > time.Now().Unix() {
			return fail(ErrConflict)
		}
		if len(g.state.Intent) > 0 {
			var intent Intent
			if canonicalIntent(g.state.Intent, o.Authority, o.Owner, &intent) != nil {
				return fail(ErrConflict)
			}
		}
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	return g, nil
}

// Verify a stored signed intent at its original validity boundary. This permits
// inspecting an old acknowledged record; it grants no current network access.
func canonicalIntent(raw, authority []byte, owner ed25519.PublicKey, out *Intent) error {
	if canonical(raw, out) != nil {
		return ErrDenied
	}
	i, _, e := VerifyIntent(raw, authority, owner, time.Unix(out.NotBefore, 0))
	if e == nil {
		*out = i
	}
	return e
}
func (g *Registry) Close() error {
	var e error
	if g.session != nil {
		e = errors.Join(e, g.session.Close())
		g.session = nil
	}
	if g.store != nil {
		e = errors.Join(e, g.store.Close())
	}
	if g.lease != nil {
		e = errors.Join(e, unix.Flock(int(g.lease.Fd()), unix.LOCK_UN), g.lease.Close())
	}
	return e
}
func (g *Registry) sessionOptions(raw []byte) SessionOptions {
	return SessionOptions{Directory: filepath.Join(g.options.Directory, "current"), Authority: g.options.Authority, Intent: raw, Owner: g.options.Owner, Replica: g.options.Replica, Initialize: true, AdmitState: g.admission("current/state"), AdmitObject: g.admission("current/objects"), RemoveObject: g.options.RemoveObject}
}
func (g *Registry) openSlot(ctx context.Context, raw []byte) (*Session, error) {
	o := g.sessionOptions(raw)
	s, e := OpenSession(ctx, o)
	if !errors.Is(e, ErrConflict) {
		return s, e
	}
	// A fence may have committed just before a crash. Only an acknowledged old
	// slot can be reused, and it is cleaned before replacing its compact record.
	meta, e := statefile.Open(filepath.Join(o.Directory, "state"), generation.MaxCatalog+2*MaxDocument+4096, false)
	if e != nil {
		return nil, e
	}
	prior, e := meta.Read("session.json")
	meta.Close()
	if e != nil {
		return nil, e
	}
	var state sessionState
	if storage.Decode(prior, &state, generation.MaxCatalog+2*MaxDocument+4096) != nil || !state.Acknowledged {
		return nil, ErrConflict
	}
	oldOptions := o
	oldOptions.Intent = state.Intent
	oldOptions.Initialize = false
	old, e := openSession(ctx, oldOptions, true)
	if e != nil {
		return nil, e
	}
	defer old.Close()
	var next Intent
	if canonical(raw, &next) != nil || next.Sequence <= old.intent.Sequence || next.Parent != old.state.Receipt.Generation {
		return nil, ErrConflict
	}
	ack, e := old.cleanupAcknowledged(ctx, 256)
	if e != nil {
		return nil, e
	}
	if !ack.Clean {
		return nil, ErrUnavailable
	}
	// No accepted objects remain. Unknown or interrupted temporary files must
	// be reconciled explicitly; they never silently become another job's data.
	d, e := old.objectRoot.Open(".")
	if e != nil {
		return nil, e
	}
	names, e := d.ReadDir(1)
	d.Close()
	if e != nil && !errors.Is(e, os.ErrNotExist) && !errors.Is(e, io.EOF) {
		return nil, e
	}
	if len(names) != 0 {
		return nil, ErrConflict
	}
	old.state = sessionState{Format: SessionFormat, Authority: bytes.Clone(o.Authority), Intent: bytes.Clone(raw), LastObserved: time.Now().Unix()}
	if e = old.save(); e != nil {
		return nil, e
	}
	if e = g.point("capture-slot-replaced"); e != nil {
		return nil, e
	}
	// OpenSession takes the same lease, so release the old handle first.
	if e = old.Close(); e != nil {
		return nil, e
	}
	old.lease = nil
	old.meta = nil
	old.objects = nil
	old.objectRoot = nil
	return OpenSession(ctx, o)
}
func (g *Registry) begin(ctx context.Context, raw []byte) (Intent, error) {
	if g.poisoned || time.Now().Unix() < g.state.ObservedUnix {
		return Intent{}, ErrConflict
	}
	i, _, e := VerifyIntent(raw, g.options.Authority, g.options.Owner, time.Now())
	if e != nil {
		return i, e
	}
	if len(g.state.Intent) > 0 && !bytes.Equal(g.state.Intent, raw) {
		var previous Intent
		if canonicalIntent(g.state.Intent, g.options.Authority, g.options.Owner, &previous) != nil || i.Sequence <= previous.Sequence {
			return i, ErrConflict
		}
		if g.session == nil {
			o := g.sessionOptions(g.state.Intent)
			o.Initialize = false
			g.session, e = openSession(ctx, o, true)
			if e != nil {
				return i, e
			}
		}
		g.session.mu.Lock()
		acked := g.session.state.Acknowledged && g.session.state.Receipt != nil && time.Now().Unix() >= g.session.state.LastObserved
		parent := ""
		if acked {
			parent = g.session.state.Receipt.Generation
		}
		g.session.mu.Unlock()
		if !acked || i.Parent != parent || i.Sequence != previous.Sequence+1 {
			return i, ErrConflict
		}
	}
	if !bytes.Equal(g.state.Intent, raw) {
		status, e := g.options.Replica.Status(ctx)
		if e != nil {
			return i, e
		}
		if i.Sequence <= status.HighestSequence || status.HighestSequence > 0 && (i.Sequence != status.HighestSequence+1 || i.Parent != status.LatestComplete) {
			return i, ErrConflict
		}
		if g.session != nil {
			if e = g.session.Close(); e != nil {
				return i, e
			}
			g.session = nil
			g.handler = nil
		}
		before := g.state
		g.state.Intent = bytes.Clone(raw)
		g.state.ObservedUnix = time.Now().Unix()
		if e = g.save(); e != nil {
			g.state = before
			return i, e
		}
		if e = g.point("capture-intent-durable"); e != nil {
			return i, e
		}
	}
	if g.session == nil {
		g.session, e = g.openSlot(ctx, raw)
		if e != nil {
			return i, e
		}
	}
	if g.handler == nil {
		s, e := NewServer(g.session, g.options.Certificate, g.options.Roots, g.options.Limits)
		if e != nil {
			g.session.Close()
			g.session = nil
			return i, e
		}
		g.handler = s.Handler
	}
	return i, nil
}
func (g *Registry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case g.gate <- struct{}{}:
		defer func() { <-g.gate }()
	default:
		w.Header().Set("Retry-After", "1")
		http.Error(w, "busy", http.StatusTooManyRequests)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if _, e := VerifyAuthority(g.options.Authority, g.options.Owner, now); e != nil {
		fail(w, e)
		return
	}
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		fail(w, ErrDenied)
		return
	}
	remote := r.TLS.PeerCertificates[0]
	if peer.Identity(remote) != g.authority.Source || now.Before(remote.NotBefore) || !now.Before(remote.NotAfter) || now.Before(g.leaf.NotBefore) || !now.Before(g.leaf.NotAfter) || r.Header.Get("Outpost-Authority") != g.state.Authority {
		fail(w, ErrDenied)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() {
		fail(w, ErrDenied)
		return
	}
	prefix := "/v1/tenants/" + g.authority.Tenant + "/domains/" + g.authority.Trust.Domain + "/captures/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		fail(w, ErrDenied)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if len(parts) < 2 || !storage.ID(parts[0]) {
		fail(w, ErrDenied)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.options.Limits.Timeout)
	defer cancel()
	if len(parts) == 2 && parts[1] == "intent" && r.Method == http.MethodPut {
		deadline, _ := ctx.Deadline()
		for _, expiry := range []time.Time{g.leaf.NotAfter, remote.NotAfter, time.Unix(g.authority.ExpiresUnix, 0)} {
			if expiry.Before(deadline) {
				deadline = expiry
			}
		}
		bounded, cleanup, e := requestLifetime(w, ctx, deadline)
		if e != nil {
			fail(w, ErrUnavailable)
			return
		}
		defer cleanup()
		ctx = bounded
		raw, e := readBody(w, r, MaxDocument)
		if e != nil {
			fail(w, e)
			return
		}
		var preview Intent
		if canonical(raw, &preview) != nil || preview.Operation != parts[0] {
			fail(w, ErrDenied)
			return
		}
		i, e := g.begin(ctx, raw)
		if e != nil {
			fail(w, e)
			return
		}
		jsonReply(w, http.StatusOK, struct {
			Operation string `json:"operation"`
			Sequence  uint64 `json:"sequence"`
		}{i.Operation, i.Sequence})
		return
	}
	var i Intent
	if canonicalIntent(g.state.Intent, g.options.Authority, g.options.Owner, &i) != nil || parts[0] != i.Operation {
		fail(w, ErrDenied)
		return
	}
	if _, e := g.begin(ctx, g.state.Intent); e != nil {
		fail(w, e)
		return
	}
	g.handler.ServeHTTP(w, r.WithContext(ctx))
}

func (c *Client) Begin(ctx context.Context) error {
	status, _, raw, e := c.request(ctx, http.MethodPut, "intent", nil, c.intentRaw, 4096)
	if e != nil {
		return e
	}
	var reply struct {
		Operation string `json:"operation"`
		Sequence  uint64 `json:"sequence"`
	}
	if status != http.StatusOK || decodeReply(raw, &reply) != nil || reply.Operation != c.intent.Operation || reply.Sequence != c.intent.Sequence {
		return ErrProtocol
	}
	return nil
}
