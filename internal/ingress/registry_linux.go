package ingress

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"golang.org/x/sys/unix"
)

const RegistryFormat = "outpost-ingress-registry-1"
const RenewedRegistryFormat = "outpost-ingress-registry-2"
const maxRegistryState = 5*MaxDocument + MaxSettlementDocument + 4096

type RegistryOptions struct {
	Parent      *os.Root
	Directory   string
	Authority   []byte
	Owner       ed25519.PublicKey
	Replica     *generation.Replica
	Certificate tls.Certificate
	Roots       *x509.CertPool
	Limits      peer.Limits
	Initialize  bool
	Staging     *StagingRoutes
	// Settlement reopens only the exact existing historical slot. It cannot
	// initialize a registry or authorize any payload route.
	Settlement, SettlementIntent []byte
	// Prefix is relative to the caller's shared capacity ledger.
	Admission func(prefix string) statefile.Admission
	// CheckRegistryWrite inspects capacity without reserving it.
	CheckRegistryWrite func(context.Context, int) error
	CheckPublication   func(context.Context, diskbudget.Peak) error
	RemoveObject       func(context.Context, string, int64) error
	recoverJournal     bool
}
type registryState struct {
	Format            string              `json:"format"`
	Authority         string              `json:"authority"`
	Intent            json.RawMessage     `json:"intent,omitempty"`
	ObservedUnix      int64               `json:"observedUnix"`
	CurrentAuthority  json.RawMessage     `json:"currentAuthority,omitempty"`
	IntentAuthority   json.RawMessage     `json:"intentAuthority,omitempty"`
	OriginalAuthority json.RawMessage     `json:"originalAuthority,omitempty"`
	PreviousAuthority json.RawMessage     `json:"previousAuthority,omitempty"`
	LegacyDigest      string              `json:"legacyDigest,omitempty"`
	LegacyRetirement  *registryRetirement `json:"legacyRetirement,omitempty"`
	JournalNode       string              `json:"journalNode,omitempty"`
}

type registryRetirement struct {
	Grant        json.RawMessage `json:"grant"`
	ObservedUnix int64           `json:"observedUnix"`
}
type Registry struct {
	root                     *os.Root
	mu                       sync.Mutex
	options                  RegistryOptions
	authority                Authority
	store                    *statefile.Store
	lease                    *os.File
	state                    registryState
	session                  *Session
	handler                  http.Handler
	leaf                     *x509.Certificate
	settlementPurpose        string
	poisoned                 bool
	journalReconstructed     bool
	gate                     chan struct{}
	stageReads, stageImports chan struct{}
	Fault                    func(string) error
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
	if len(raw) > maxRegistryState {
		return statefile.ErrCapacity
	}
	if g.state.JournalNode != "" {
		e = g.writeJournalCopy(raw)
	}
	if e == nil {
		e = g.store.Write("registry.json", raw)
	}
	if e != nil {
		g.poisoned = true
	}
	return e
}
func OpenRegistry(ctx context.Context, o RegistryOptions) (*Registry, error) {
	return openRegistry(ctx, o, false)
}

// historical is private to explicit offline maintenance. No network handler is
// exposed before the caller closes the returned registry.
func openRegistry(ctx context.Context, o RegistryOptions, historical bool) (*Registry, error) {
	a, e := VerifyAuthority(o.Authority, o.Owner, time.Now())
	if historical {
		if o.Initialize || len(o.Settlement)+len(o.SettlementIntent) != 0 {
			return nil, ErrDenied
		}
		a, e = VerifyAuthorityDocument(o.Authority, o.Owner)
	}
	if len(o.Settlement) != 0 {
		if o.Initialize {
			return nil, ErrDenied
		}
		if _, err := VerifySettlement(o.Settlement, o.Authority, o.SettlementIntent, o.Owner, time.Now()); err != nil {
			return nil, err
		}
		a, e = VerifyAuthorityDocument(o.Authority, o.Owner)
	} else if len(o.SettlementIntent) != 0 {
		return nil, ErrDenied
	}
	if e != nil {
		return nil, e
	}
	if o.Replica == nil || !limitsOK(o.Limits) {
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
	r, e := localfs.Directory(o.Parent, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	// Transferred to the instance only after the lease is held.
	owned := false
	defer func() {
		if !owned {
			r.Close()
		}
	}()
	i, e := r.Stat(".")
	if e != nil || !i.IsDir() || i.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}

	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_NONBLOCK
	if o.Initialize {
		flags |= os.O_CREATE
	}
	lease, e := localfs.OpenFile(r, ".registry-lock", flags, 0600)
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
	o.Settlement = bytes.Clone(o.Settlement)
	o.SettlementIntent = bytes.Clone(o.SettlementIntent)
	owned = true
	g := &Registry{root: r, options: o, authority: a, leaf: leaf, lease: lease, gate: make(chan struct{}, 1)}
	if o.Staging != nil {
		g.stageReads = make(chan struct{}, o.Limits.Concurrency)
		g.stageImports = make(chan struct{}, o.Limits.Concurrency)
	}
	fail := func(e error) (*Registry, error) { g.Close(); return nil, e }
	g.store, e = statefile.OpenAt(r, "state", maxRegistryJournal, o.Initialize)
	if e != nil {
		return fail(e)
	}
	g.store.Admit = g.admission("state")
	raw, e := g.store.Read("registry.json")
	if o.recoverJournal {
		raw, g.journalReconstructed, e = g.recoverJournal(ctx, raw, e)
	}
	if errors.Is(e, os.ErrNotExist) && o.Initialize {
		for _, name := range []string{registryJournalCopyName, registryJournalAnchorName} {
			if _, err := g.store.Read(name); !errors.Is(err, os.ErrNotExist) {
				return fail(ErrRegistryRecovery)
			}
		}
		g.state = registryState{Format: RegistryFormat, Authority: storage.Hash(o.Authority), ObservedUnix: time.Now().Unix()}
		if e = g.save(); e != nil {
			return fail(e)
		}
	} else if e != nil {
		if errors.Is(e, os.ErrNotExist) {
			if _, err := g.store.Read(registryJournalCopyName); !errors.Is(err, os.ErrNotExist) {
				return fail(errors.Join(ErrRegistryRecovery, e))
			}
		}
		return fail(e)
	} else {
		if e = g.loadRegistry(raw); e != nil {
			return fail(e)
		}
		if e = g.checkJournalCopy(raw); e != nil {
			return fail(e)
		}
	}
	if len(o.Settlement) != 0 {
		grant, err := VerifySettlement(o.Settlement, o.Authority, o.SettlementIntent, o.Owner, time.Now())
		if err != nil || !grant.inspect() && !bytes.Equal(g.state.Intent, o.SettlementIntent) {
			return fail(ErrConflict)
		}
		g.settlementPurpose = grant.Purpose
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
	if g.root != nil {
		e = errors.Join(e, g.root.Close())
		g.root = nil
	}
	return e
}
func (g *Registry) sessionOptions(raw []byte) SessionOptions {
	authority := g.options.Authority
	if bytes.Equal(raw, g.state.Intent) {
		authority = g.intentAuthority()
	}
	return SessionOptions{Parent: g.root, Directory: "current", Authority: authority, Intent: raw, Owner: g.options.Owner, Replica: g.options.Replica, Initialize: true, AdmitState: g.admission("current/state"), AdmitObject: g.admission("current/objects"), RemoveObject: g.options.RemoveObject, CheckPublication: g.options.CheckPublication}
}

func (g *Registry) sessionServer() (*http.Server, error) {
	o := g.options
	if o.Staging == nil {
		return NewServer(g.session, o.Certificate, o.Roots, o.Limits)
	}
	// Materialization uses the existing durable verification cursor. Keep
	// each staged-capture request small even on synchronous receiver disks.
	return newServer(g.session, o.Certificate, o.Roots, o.Limits, 1, generation.MaxObject)
}
func (g *Registry) openSlot(ctx context.Context, raw []byte) (*Session, error) {
	o := g.sessionOptions(raw)
	s, e := OpenSession(ctx, o)
	if !errors.Is(e, ErrConflict) {
		if e == nil {
			s.Fault = g.point
		}
		return s, e
	}
	// A fence may have committed before a crash. Reuse only an acknowledged,
	// reclaimed or explicitly retired old slot after bounded cleanup.
	meta, e := statefile.OpenAt(g.root, "current/state", maxSessionDocument, false)
	if e != nil {
		return nil, e
	}
	prior, e := meta.Read("session.json")
	meta.Close()
	if e != nil {
		return nil, e
	}
	var state sessionState
	if storage.Decode(prior, &state, maxSessionDocument) != nil || !state.Acknowledged && len(state.Reclaimed) == 0 && len(state.Retired) == 0 {
		return nil, ErrConflict
	}
	oldOptions := o
	oldAuthority, e := VerifyAuthorityDocument(state.Authority, g.options.Owner)
	if e != nil || !SameAuthorityScope(oldAuthority, g.authority) || oldAuthority.Revision > g.authority.Revision || oldAuthority.Revision == g.authority.Revision && !bytes.Equal(state.Authority, g.options.Authority) {
		return nil, ErrConflict
	}
	oldOptions.Authority = bytes.Clone(state.Authority)
	oldOptions.Intent = state.Intent
	oldOptions.Initialize = false
	mode := sessionComplete
	if len(state.Reclaimed) != 0 || len(state.Retired) != 0 {
		mode = sessionInspect
	}
	old, e := openSessionFor(ctx, oldOptions, mode)
	if e != nil {
		return nil, e
	}
	defer old.Close()
	var next Intent
	if canonical(raw, &next) != nil {
		return nil, ErrConflict
	}
	if len(state.Retired) != 0 {
		if next.Sequence != old.intent.Sequence || next.Parent != old.intent.Parent || next.Operation == old.intent.Operation {
			return nil, ErrConflict
		}
	} else if next.Sequence <= old.intent.Sequence {
		return nil, ErrConflict
	}
	if e = g.checkPredecessor(ctx, next); e != nil {
		return nil, e
	}
	if e = old.cleanupStaged(ctx, 256); e != nil {
		return nil, e
	}
	if len(old.refs) != 0 {
		return nil, ErrUnavailable
	}
	if empty, err := old.slotEmpty(); err != nil || !empty {
		return nil, errors.Join(ErrConflict, err)
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
	s, e = OpenSession(ctx, o)
	if e == nil {
		s.Fault = g.point
	}
	return s, e
}
func (g *Registry) nextRegistryState(raw []byte) registryState {
	next := g.state
	next.Intent = bytes.Clone(raw)
	if next.Format == RenewedRegistryFormat {
		next.IntentAuthority = bytes.Clone(g.options.Authority)
	}
	next.ObservedUnix = time.Now().Unix()
	return next
}

func (g *Registry) begin(ctx context.Context, raw []byte) (Intent, error) {
	if g.poisoned || time.Now().Unix() < g.state.ObservedUnix {
		return Intent{}, ErrConflict
	}
	i, _, e := VerifyIntent(raw, g.options.Authority, g.options.Owner, time.Now())
	if e != nil {
		return i, e
	}
	if e = g.checkAdmission(ctx, raw, i); e != nil {
		return i, e
	}
	if !bytes.Equal(g.state.Intent, raw) {
		if g.session != nil {
			if e = g.session.Close(); e != nil {
				return i, e
			}
			g.session = nil
			g.handler = nil
		}
		before := g.state
		g.state = g.nextRegistryState(raw)
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
		s, e := g.sessionServer()
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
	if g.options.Staging != nil && (len(g.options.Settlement) == 0 || g.settlementPurpose == SettlementPublish) && g.serveStaging(w, r) {
		return
	}
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
	if len(g.options.Settlement) != 0 {
		g.serveSettlement(w, r)
		return
	}
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
	if peer.Identity(remote) != g.authority.Source || now.Before(remote.NotBefore) || !now.Before(remote.NotAfter) || now.Before(g.leaf.NotBefore) || !now.Before(g.leaf.NotAfter) {
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
	if len(parts) == 2 && parts[1] == "reclaim" && r.Method == http.MethodPut {
		g.serveReclaim(w, r.WithContext(ctx), parts[0])
		return
	}
	if r.Header.Get("Outpost-Authority") != g.state.Authority {
		fail(w, ErrDenied)
		return
	}
	if len(parts) == 2 && (parts[1] == "intent" || parts[1] == "readiness") && r.Method == http.MethodPut {
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
		var i Intent
		if parts[1] == "readiness" {
			i, _, e = VerifyIntent(raw, g.options.Authority, g.options.Owner, time.Now())
			if e == nil {
				e = g.checkAdmission(ctx, raw, i)
			}
		} else {
			i, e = g.begin(ctx, raw)
		}
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
	if len(parts) == 2 && parts[1] == "ack" && r.Method == http.MethodPut {
		// Cleanup cannot initialize or replace the fenced slot. Current owner
		// authority and TLS were checked above; the receipt is checked by Session.
		if g.poisoned || now.Unix() < g.state.ObservedUnix {
			fail(w, ErrConflict)
			return
		}
		if g.session == nil {
			o := g.sessionOptions(g.state.Intent)
			o.Initialize = false
			var e error
			g.session, e = openSession(ctx, o, true)
			if e != nil {
				fail(w, e)
				return
			}
		}
		if g.handler == nil {
			s, e := g.sessionServer()
			if e != nil {
				fail(w, e)
				return
			}
			g.handler = s.Handler
		}
	} else {
		if _, e := g.begin(ctx, g.state.Intent); e != nil {
			fail(w, e)
			return
		}
	}
	if len(parts) == 2 && (parts[1] == "coverage" || parts[1] == "partition") && r.Method == http.MethodPut {
		g.serveCoverage(w, r.WithContext(ctx), i, remote.NotAfter, parts[1] == "partition")
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
