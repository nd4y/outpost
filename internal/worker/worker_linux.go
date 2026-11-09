package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/recovery"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

type Options struct {
	// Root is an independently admitted, already opened worker directory.
	// Open retains its own descriptor; the caller retains Root.
	Root        *os.Root
	Guard       func(context.Context) error
	Directory   string
	Node        string
	Owner       ed25519.PublicKey
	Certificate tls.Certificate
	Roots       *x509.CertPool
	Initialize  bool
	Recovery    *recovery.Executor
	Fetcher     *control.Fetcher
	// Resolve is local, bounded and context-aware. No secrets enter shared state.
	Resolve func(context.Context, storage.Profile) (*storage.Backend, error)
}
type domainState struct {
	replica *generation.Replica
	journal *peer.Journal
	handler http.Handler
	ingress *ingress.Registry
}

var externalQueueLimits = upload.QueueLimits{MaxJobs: 1, Parallel: 1, AttemptMillis: 300000, RetryBaseMillis: 1000, RetryMaxMillis: 60000}

type view struct {
	cfg                   control.Config
	autonomy              *control.Autonomy
	ctx                   context.Context
	cancel                context.CancelFunc
	done                  chan struct{}
	err                   error
	requests              sync.WaitGroup
	metadata              chan struct{}
	domains               map[string]*domainState
	controls              *Controls
	requestGates          map[string]*storage.RequestGate
	nextScrubScan         time.Time
	nextExternalAuditScan time.Time
}
type Worker struct {
	// Fault is a local test hook, never accepted from shared configuration.
	Fault        func(string) error
	root         *os.Root
	guard        func(context.Context) error
	budgetMu     sync.Mutex
	dir, node    string
	cert         tls.Certificate
	roots        *x509.CertPool
	cache        *control.Cache
	state, lease *statefile.Store
	fetcher      *control.Fetcher
	resolve      func(context.Context, storage.Profile) (*storage.Backend, error)
	// Only the execution lease owner replaces this map. Each view reads its own map.
	requestGates map[string]*storage.RequestGate
	mu           sync.Mutex
	active       *view
	budget       *diskbudget.Budget
	owner        ed25519.PublicKey
	recovery     *recovery.Executor
}

func Open(o Options) (*Worker, error) {
	if o.Recovery != nil && o.Recovery.NodeIdentity() != o.Node {
		return nil, ErrDenied
	}
	if !filepath.IsAbs(o.Directory) || !storage.ID(o.Node) || len(o.Owner) != 32 || len(o.Certificate.Certificate) == 0 || o.Roots == nil {
		return nil, ErrDenied
	}
	leaf, e := x509.ParseCertificate(o.Certificate.Certificate[0])
	if e != nil || peer.Identity(leaf) != o.Node {
		return nil, ErrDenied
	}
	private, ok := o.Certificate.PrivateKey.(ed25519.PrivateKey)
	public, publicOK := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !publicOK || len(private) != ed25519.PrivateKeySize || !bytes.Equal(public, private.Public().(ed25519.PublicKey)) {
		return nil, ErrDenied
	}
	w := &Worker{recovery: o.Recovery, guard: o.Guard, dir: o.Directory, node: o.Node, cert: o.Certificate, roots: o.Roots.Clone(), fetcher: o.Fetcher, resolve: o.Resolve, owner: append(ed25519.PublicKey(nil), o.Owner...)}
	if e = w.check(context.Background()); e != nil {
		return nil, e
	}
	if o.Root != nil {
		w.root, e = localfs.OpenAt(o.Root, ".", false)
	} else {
		if o.Initialize {
			if _, err := os.Lstat(o.Directory); !errors.Is(err, os.ErrNotExist) {
				return nil, ErrDenied
			}
		}
		w.root, e = localfs.Directory(nil, o.Directory, o.Initialize)
	}
	if e != nil {
		return nil, e
	}

	w.state, e = statefile.OpenAt(w.root, "state", 32<<20, o.Initialize)
	if e != nil {
		w.root.Close()
		return nil, e
	}
	fail := func(e error) (*Worker, error) { w.Close(); return nil, e }
	if e = w.initState(o.Initialize); e != nil {
		return fail(e)
	}
	status, e := w.Status(context.Background())
	if e != nil {
		return fail(e)
	}
	if status.Controls != nil {
		commands, err := statefile.OpenAt(w.root, "commands/poll", 4096, false)
		if err != nil {
			return fail(err)
		}
		if err = commands.Close(); err != nil {
			return fail(err)
		}
	}
	w.lease, e = statefile.OpenAt(w.root, "lease", 4096, o.Initialize)
	if e != nil {
		return fail(e)
	}
	w.cache, e = control.OpenCacheAt(w.root, "control", o.Node, o.Owner, o.Initialize)
	if e != nil {
		return fail(e)
	}
	return w, nil
}

// Close is called only after Run and the serving HTTP server have stopped.
func (w *Worker) Close() error {
	var e error
	if w.cache != nil {
		e = errors.Join(e, w.cache.Close())
	}
	if w.state != nil {
		e = errors.Join(e, w.state.Close())
	}
	if w.lease != nil {
		e = errors.Join(e, w.lease.Close())
	}
	if w.budget != nil {
		e = errors.Join(e, w.budget.Close())
	}
	if w.root != nil {
		e = errors.Join(e, w.root.Close())
	}
	return e
}
func (w *Worker) Accept(ctx context.Context, raw []byte) error {
	if e := w.check(ctx); e != nil {
		return e
	}
	c, e := w.cache.Verify(raw)
	if e != nil {
		return e
	}
	_, e = w.cache.Raw(ctx)
	initialize := errors.Is(e, control.ErrInactive)
	if e != nil && !initialize {
		return e
	}
	if _, e = w.budgetFor(ctx, c, initialize); e != nil {
		return e
	}
	return w.cache.Accept(ctx, raw, time.Now())
}
func (w *Worker) budgetFor(ctx context.Context, c control.Config, initialize bool) (*diskbudget.Budget, error) {
	w.budgetMu.Lock()
	defer w.budgetMu.Unlock()
	if w.budget == nil {
		limits := diskbudget.Limits{Capacity: c.Limits.CapacityBytes, Reserve: c.Limits.ReserveBytes, Spool: c.Limits.SpoolBytes, Telemetry: c.Limits.TelemetryBytes}
		b, e := diskbudget.OpenAt(w.root, ctx, ".", limits, initialize)
		if e != nil {
			return nil, e
		}
		s, e := b.Status(ctx)
		if e == nil && len(s.Pending) > 0 {
			e = b.Reconcile(ctx, s.Limits)
		}
		if e != nil {
			b.Close()
			return nil, e
		}
		w.budget = b
	}
	if e := w.state.SetAdmission(ctx, w.admission("state")); e != nil {
		return nil, e
	}
	if e := w.cache.SetAdmission(ctx, w.admission("control")); e != nil {
		return nil, e
	}
	return w.budget, nil
}
func DomainDirectory(root string, t generation.Trust) string {
	return filepath.Join(root, "domains", t.Domain, t.Repository, strconv.FormatUint(t.Epoch, 10))
}
func (w *Worker) check(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if w.guard != nil {
		return w.guard(ctx)
	}
	return nil
}
func (w *Worker) relative(dir string) string {
	rel, e := filepath.Rel(w.dir, dir)
	if e != nil {
		return ""
	}
	return rel
}
func (w *Worker) admission(prefix string) statefile.Admission {
	return func(name string, size int) (func(bool) error, error) {
		if e := w.check(context.Background()); e != nil {
			return nil, e
		}
		if w.budget == nil {
			return nil, ErrDenied
		}
		finish, e := w.budget.Admission(prefix)(name, size)
		if e != nil {
			return nil, e
		}
		return func(written bool) error { return errors.Join(finish(written), w.check(context.Background())) }, nil
	}
}
func (w *Worker) createOrOpen(ctx context.Context, dir string, open func(bool) error) error {
	if e := w.check(ctx); e != nil {
		return e
	}
	relative := w.relative(dir)
	parent, e := localfs.OpenAt(w.root, filepath.Dir(relative), true)
	if e != nil {
		return e
	}
	defer parent.Close()
	e = parent.Mkdir(filepath.Base(relative), 0700)
	initialize := e == nil
	if e != nil && !errors.Is(e, os.ErrExist) {
		return e
	}
	d, e := parent.Open(".")
	if e != nil {
		return e
	}
	e = errors.Join(d.Sync(), d.Close())
	if e != nil {
		return e
	}
	return open(initialize)
}
func peerPolicy(c control.Config, d control.Domain, self string, inbound bool, job control.Job) peer.Policy {
	node, _ := c.NodeByID(self)
	p := peer.Policy{Self: self, Class: node.Class, Domain: d.Trust.Domain, Repository: d.Trust.Repository, Epoch: d.Trust.Epoch, Peers: map[string]peer.Grant{}}
	for _, class := range d.Placement.AllowedClasses {
		if class != "external" {
			p.AllowedClasses = append(p.AllowedClasses, class)
		}
	}
	if !inbound {
		p.ReadbackMaxAgeSeconds = d.PeerReadbackMaxAgeSeconds
		p.RequiredRevision = job.PeerRevision
		n, _ := c.NodeByID(job.Peer)
		p.Peers[job.Peer] = peer.Grant{Class: n.Class, Push: job.Kind == "push", Pull: true, History: c.Autonomous(job), Repair: job.Repair != "", ExpiresUnix: c.ExpiresUnix}
		return p
	}
	for _, j := range c.Jobs {
		if j.Domain != d.Trust.Domain || j.Peer != self || j.Executor == self || j.Kind != "push" && j.Kind != "pull" {
			continue
		}
		n, _ := c.NodeByID(j.Executor)
		g := p.Peers[j.Executor]
		g.Class = n.Class
		g.ExpiresUnix = c.ExpiresUnix
		g.Repair = g.Repair || j.Repair != ""
		if j.Kind == "push" {
			g.Push = true
			// The transport requires read authority for full readback. The outer
			// handler still restricts it to this exact signed push operation.
			g.Pull = true
		} else {
			g.Pull = true
		}
		p.Peers[j.Executor] = g
	}
	for _, rule := range c.Replication {
		if rule.Domain != d.Trust.Domain || rule.Peer() != self {
			continue
		}
		n, _ := c.NodeByID(rule.Executor())
		g := p.Peers[rule.Executor()]
		g.Class = n.Class
		g.ExpiresUnix = c.ExpiresUnix
		g.History = true
		g.Repair = g.Repair || rule.Repair
		g.Pull = true
		if rule.Mode == "push" {
			g.Push = true
		}
		p.Peers[rule.Executor()] = g
	}
	return p
}
func (w *Worker) start(ctx context.Context, c control.Config) (*view, error) {
	status, e := w.Status(ctx)
	if e != nil {
		return nil, e
	}
	if status.Controls == nil && len(c.Commands) > 0 {
		return nil, ErrDenied
	}
	v := &view{cfg: c, done: make(chan struct{}), metadata: make(chan struct{}, c.Limits.Parallel), domains: map[string]*domainState{}, controls: status.Controls}
	var compileError error
	v.autonomy, compileError = c.CompileAutonomy()
	if compileError != nil {
		return nil, compileError
	}
	v.requestGates = make(map[string]*storage.RequestGate, len(c.Targets))
	for _, target := range c.Targets {
		gate := w.requestGates[target.ID]
		if gate == nil {
			gate, e = storage.NewRequestGate(target.Profile)
			if e != nil {
				return nil, e
			}
		}
		v.requestGates[target.ID] = gate
	}
	v.ctx, v.cancel = context.WithDeadline(ctx, time.Unix(c.ExpiresUnix, 0))
	fail := func(e error) (*view, error) {
		v.cancel()
		for _, d := range v.domains {
			if d.ingress != nil {
				d.ingress.Close()
			}
			if d.journal != nil {
				d.journal.Close()
			}
			if d.replica != nil {
				d.replica.Close()
			}
		}
		return nil, e
	}
	for _, d := range c.Domains {
		if !d.Placement.PermitsNode(w.node) {
			continue
		}
		local := &domainState{}
		v.domains[d.Trust.Domain] = local
		dir := DomainDirectory(w.dir, d.Trust)
		e := w.createOrOpen(ctx, filepath.Join(dir, "replica"), func(init bool) error {
			var e error
			local.replica, e = generation.OpenAt(w.root, w.relative(filepath.Join(dir, "replica")), d.Trust, init)
			return e
		})
		if e != nil {
			return fail(e)
		}
		e = w.createOrOpen(ctx, filepath.Join(dir, "peer"), func(init bool) error {
			var e error
			local.journal, e = peer.OpenJournalAt(w.root, w.relative(filepath.Join(dir, "peer")), w.node, d.Trust, init)
			return e
		})
		if e != nil {
			return fail(e)
		}
		p := peerPolicy(c, d, w.node, true, control.Job{})
		if len(p.Peers) > 0 {
			s, e := peer.NewServer(local.replica, local.journal, p, w.cert, w.roots, peer.Limits{Concurrency: c.Limits.Parallel, Timeout: time.Duration(c.Limits.AttemptMillis) * time.Millisecond, Attempts: 2})
			if e != nil {
				return fail(e)
			}
			local.handler = s.Handler
		}
	}
	limits := diskbudget.Limits{Capacity: c.Limits.CapacityBytes, Reserve: c.Limits.ReserveBytes, Spool: c.Limits.SpoolBytes, Telemetry: c.Limits.TelemetryBytes}
	if _, e := w.budgetFor(ctx, c, false); e != nil {
		return fail(e)
	}
	if e := w.budget.Reconcile(ctx, limits); e != nil {
		return fail(e)
	}
	if e := w.state.SetAdmission(ctx, w.admission("state")); e != nil {
		return fail(e)
	}
	if e := w.cache.SetAdmission(ctx, w.admission("control")); e != nil {
		return fail(e)
	}
	for id, local := range v.domains {
		d, _ := c.DomainByID(id)
		relative, e := filepath.Rel(w.dir, DomainDirectory(w.dir, d.Trust))
		if e != nil {
			return fail(e)
		}
		local.replica.Admit = w.admission(filepath.ToSlash(filepath.Join(relative, "replica")))
		local.journal.Admit = w.admission(filepath.ToSlash(filepath.Join(relative, "peer")))
	}
	for _, raw := range c.Ingress {
		a, e := ingress.VerifyAuthority(raw, w.owner, time.Now())
		if e != nil {
			return fail(e)
		}
		if a.Ingress != w.node {
			continue
		}
		local := v.domains[a.Trust.Domain]
		if local == nil {
			return fail(ErrDenied)
		}
		dir := filepath.Join(DomainDirectory(w.dir, a.Trust), "ingress")
		relative, e := filepath.Rel(w.dir, dir)
		if e != nil {
			return fail(e)
		}
		e = w.createOrOpen(ctx, dir, func(init bool) error {
			var e error
			local.ingress, e = ingress.OpenRegistry(v.ctx, ingress.RegistryOptions{Parent: w.root, Directory: w.relative(dir), Authority: raw, Owner: w.owner, Replica: local.replica, Certificate: w.cert, Roots: w.roots, Initialize: init, Staging: captureStagingRoutes(c, a.Trust.Domain), Limits: peer.Limits{Concurrency: c.Limits.Parallel, Timeout: time.Duration(c.Limits.AttemptMillis) * time.Millisecond, Attempts: 2}, Admission: func(prefix string) statefile.Admission {
				return w.admission(filepath.ToSlash(filepath.Join(relative, prefix)))
			}, CheckRegistryWrite: func(ctx context.Context, size int) error {
				if e := w.check(ctx); e != nil {
					return e
				}
				if w.budget == nil {
					return ErrDenied
				}
				return w.budget.CheckWrite(ctx, filepath.ToSlash(filepath.Join(relative, "registry.json")), size)
			}, RemoveObject: func(ctx context.Context, name string, size int64) error {
				if e := w.check(ctx); e != nil {
					return e
				}
				return w.budget.Remove(ctx, filepath.ToSlash(filepath.Join(relative, "current/objects", name)), size)
			}})
			return e
		})
		if e != nil {
			return fail(e)
		}
	}
	if e := w.openSettlements(v); e != nil {
		return fail(e)
	}
	// Local development fault hooks never enter signed configuration.
	for _, local := range v.domains {
		if local.ingress != nil {
			local.ingress.Fault = w.Fault
		}
	}
	if e := w.admit(ctx, c); e != nil {
		return fail(e)
	}
	if e := w.resetDiscovery(ctx, v); e != nil {
		return fail(e)
	}
	w.requestGates = v.requestGates
	w.mu.Lock()
	w.active = v
	w.mu.Unlock()
	go func() {
		discovery := make(chan error, 1)
		go func() { discovery <- w.discover(v) }()
		observations := make(chan error, 1)
		go func() { observations <- w.observe(v) }()
		v.err = w.jobs(v)
		v.cancel()
		v.err = errors.Join(v.err, <-discovery, <-observations)
		close(v.done)
	}()
	return v, nil
}
func (w *Worker) stop(v *view) error {
	if v == nil {
		return nil
	}
	w.mu.Lock()
	if w.active == v {
		w.active = nil
	}
	v.cancel()
	w.mu.Unlock()
	<-v.done
	e := v.err
	v.requests.Wait()
	for _, d := range v.domains {
		if d.ingress != nil {
			e = errors.Join(e, d.ingress.Close())
		}
		e = errors.Join(e, d.journal.Close(), d.replica.Close())
	}
	return e
}

// Run keeps using the cached unexpired policy while the controller is absent.
// A new revision cancels and joins all old attempts before starting new work.
func (w *Worker) Run(ctx context.Context) (result error) {
	parent := ctx
	defer func() {
		if parent.Err() != nil && cancellationOnly(result) {
			result = nil
		}
	}()
	if e := w.check(ctx); e != nil {
		return e
	}
	initial, e := w.Status(ctx)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancelCause(ctx)
	monitorDone := make(chan struct{})
	controlChanged := make(chan struct{}, 1)
	var fetchMu sync.Mutex
	var cancelFetch context.CancelFunc
	go func() {
		defer close(monitorDone)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		observed := controlRevision(initial.Controls)
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if e := w.check(ctx); e != nil {
					cancel(e)
					return
				}
				s, e := w.Status(ctx)
				if e != nil {
					if ctx.Err() == nil {
						cancel(e)
					}
					return
				}
				revision := controlRevision(s.Controls)
				w.mu.Lock()
				active := w.active
				stale := active != nil && controlRevision(active.controls) != revision
				if stale {
					active.cancel()
				}
				w.mu.Unlock()
				if revision != observed || stale {
					observed = revision
					select {
					case controlChanged <- struct{}{}:
					default:
					}
					fetchMu.Lock()
					if cancelFetch != nil {
						cancelFetch()
					}
					fetchMu.Unlock()
				}
			}
		}
	}()
	defer func() {
		cause := context.Cause(ctx)
		cancel(context.Canceled)
		<-monitorDone
		if parent.Err() == nil && cause != nil && !errors.Is(cause, context.Canceled) {
			result = errors.Join(result, cause)
		}
	}()

	e = w.lease.WithLock(ctx, func() (runErr error) {
		// A reopened process must install existing quota admission before its
		// first control reconciliation, including the deferred quiescence write.
		// Reconciliation belongs to this exclusive execution owner, never a
		// concurrent reporting or command process.
		cached, err := w.cache.Raw(ctx)
		if err == nil {
			known, err := w.cache.Verify(cached)
			if err != nil {
				return err
			}
			if _, err = w.budgetFor(ctx, known, false); err != nil {
				return err
			}
		} else if !errors.Is(err, control.ErrInactive) {
			return err
		}
		var active *view
		defer func() {
			if ctx.Err() != nil && (runErr == context.Canceled || runErr == context.DeadlineExceeded) {
				runErr = nil
			}
			if stopErr := w.stop(active); stopErr != nil {
				runErr = errors.Join(runErr, stopErr)
			}
			// Only successful joining proves that no old operation is running.
			if runErr == nil {
				bounded, done := context.WithTimeout(context.Background(), 5*time.Second)
				runErr = w.markControlsApplied(bounded)
				done()
			}
		}()
		poll := time.Second
		stop := func() error { old := active; active = nil; return w.stop(old) }
		reconcileControls := func() error {
			s, e := w.Status(ctx)
			if e != nil {
				return e
			}
			if active != nil && controlRevision(active.controls) != controlRevision(s.Controls) {
				if e = stop(); e != nil {
					return e
				}
			}
			if active == nil {
				if e = w.reconcileActions(ctx); e != nil {
					return e
				}
				return w.markControlsApplied(ctx)
			}
			return nil
		}
		for {
			if ctx.Err() != nil {
				return nil
			}
			if e := reconcileControls(); e != nil {
				return e
			}
			if w.fetcher != nil {
				fetchCtx, doneFetch := context.WithTimeout(ctx, 5*time.Second)
				fetchMu.Lock()
				cancelFetch = doneFetch
				fetchMu.Unlock()
				raw, e := w.fetcher.Fetch(fetchCtx)
				fetchMu.Lock()
				cancelFetch = nil
				fetchMu.Unlock()
				doneFetch()
				if e == nil {
					_ = w.Accept(ctx, raw)
				}
			}
			if e := reconcileControls(); e != nil {
				return e
			}
			c, e := w.cache.Current(ctx, time.Now())
			if e != nil {
				if err := stop(); err != nil {
					return err
				}
				if err := w.update(ctx, func(s *Status) error { s.Phase = errorCode(e); return nil }); err != nil {
					return err
				}
				poll = time.Second
			} else {
				poll = time.Duration(c.Limits.PollSeconds) * time.Second
				if active == nil || active.cfg.Revision != c.Revision {
					if err := stop(); err != nil {
						return err
					}
					active, e = w.start(ctx, c)
					if e != nil {
						return e
					}
				}
			}
			var done <-chan struct{}
			if active != nil {
				done = active.done
			}
			timer := time.NewTimer(poll)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-done:
				timer.Stop()
				if err := stop(); err != nil {
					return err
				}
			case <-controlChanged:
				timer.Stop()
			case <-timer.C:
			}
		}
	})
	if e == ctx.Err() && ctx.Err() != nil {
		return nil
	}
	return e
}

// A wrapped/joined parent cancellation is an orderly stop. A mixed error tree
// still reports its independent failure (for example a failed durable write).
func cancellationOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		children := joined.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !cancellationOnly(child) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return cancellationOnly(wrapped.Unwrap())
	}
	return err == context.Canceled || err == context.DeadlineExceeded
}

// ServeHTTP delegates only exact signed inbound jobs. It cannot be used as a
// generic authenticated object server or as an implicit reverse route.
func (w *Worker) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	if w.check(r.Context()) != nil {
		http.Error(out, "unavailable", 503)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(out, "denied", 403)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) >= 4 && parts[1] == "v1" && parts[3] == "observations" {
		w.serveObservations(out, r, parts)
		return
	}
	if len(parts) == 4 && parts[1] == "v1" && parts[3] == "inventory" {
		w.serveInventory(out, r, parts[2])
		return
	}
	if len(parts) == 4 && parts[1] == "v1" && parts[3] == "repair-needs" {
		w.serveDiscovery(out, r, parts[2], true)
		return
	}
	if len(parts) >= 8 && parts[1] == "v1" && parts[2] == "tenants" && parts[4] == "domains" && parts[6] == "captures" {
		w.serveIngress(out, r, parts[5])
		return
	}
	if len(parts) < 6 || parts[1] != "v1" || parts[3] != "generations" {
		http.Error(out, "denied", 403)
		return
	}
	remote := peer.Identity(r.TLS.PeerCertificates[0])
	w.mu.Lock()
	v := w.active
	if v == nil || v.ctx.Err() != nil || v.cfg.Active(time.Now()) != nil {
		w.mu.Unlock()
		http.Error(out, "inactive", 503)
		return
	}
	d := v.domains[parts[2]]
	if required, e := strconv.ParseUint(r.Header.Get("Outpost-Required-Revision"), 10, 64); e == nil && required > v.cfg.Revision {
		if _, known := v.cfg.NodeByID(remote); known {
			w.mu.Unlock()
			out.Header().Set("Retry-After", "1")
			http.Error(out, "configuration pending", http.StatusServiceUnavailable)
			return
		}
	}
	allowed := false
	for _, j := range v.cfg.Jobs {
		if j.Peer == w.node && j.Executor == remote && j.Domain == parts[2] && j.Generation == parts[4] && j.Operation == r.Header.Get("Outpost-Operation") && j.Kind == r.Header.Get("Outpost-Mode") && j.Repair == r.Header.Get("Outpost-Repair") {
			allowed = true
			break
		}
	}
	if !allowed {
		domain, ok := v.cfg.DomainByID(parts[2])
		if ok {
			for _, rule := range v.cfg.Replication {
				if rule.Domain != parts[2] || rule.Peer() != w.node || rule.Executor() != remote || rule.Mode != r.Header.Get("Outpost-Mode") {
					continue
				}
				j := rule.Job(domain.Trust, parts[4])
				if token := r.Header.Get("Outpost-Repair"); token != "" {
					if !rule.Repair || !storage.ID(token) {
						continue
					}
					j = rule.RepairJob(domain.Trust, parts[4], token)
				}
				if storage.ID(parts[4]) && j.Operation == r.Header.Get("Outpost-Operation") {
					allowed = true
					break
				}
			}
		}
	}
	if !allowed || d == nil || d.handler == nil || v.paused(parts[2], r.Header.Get("Outpost-Operation")) {
		w.mu.Unlock()
		http.Error(out, "denied", 403)
		return
	}
	v.requests.Add(1)
	w.mu.Unlock()
	defer v.requests.Done()
	ctx, cleanup, e := w.requestContext(out, r, v)
	if e != nil {
		http.Error(out, "unavailable", 503)
		return
	}
	defer cleanup()
	d.handler.ServeHTTP(out, r.WithContext(ctx))
}
func (w *Worker) HTTPServer() (*http.Server, error) {
	cfg, e := control.ServerTLS(w.cert, w.roots, w.node)
	if e != nil {
		return nil, e
	}
	return &http.Server{Handler: w, TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}, nil
}
func (w *Worker) attempt(ctx context.Context, v *view, j control.Job) (json.RawMessage, error) {
	d, ok := v.cfg.DomainByID(j.Domain)
	local := v.domains[j.Domain]
	if !ok || local == nil {
		return nil, ErrDenied
	}
	if j.Kind == "push" || j.Kind == "pull" {
		n, _ := v.cfg.NodeByID(j.Peer)
		client, e := peer.NewClient(n.Endpoint, j.Peer, w.cert, w.roots, peerPolicy(v.cfg, d, w.node, false, j), local.journal, d.Trust, peer.Limits{Concurrency: v.cfg.Limits.Parallel, Timeout: time.Duration(v.cfg.Limits.AttemptMillis) * time.Millisecond, Attempts: 2})
		if e != nil {
			return nil, e
		}
		defer client.Close()
		var result peer.Result
		if j.Repair != "" && j.Kind == "push" {
			result, e = client.RepairPush(ctx, j.Operation, j.Generation, j.Repair, local.replica)
		} else if j.Repair != "" {
			result, e = client.RepairPull(ctx, j.Operation, j.Generation, j.Repair, local.replica)
		} else if j.Kind == "push" {
			result, e = client.Push(ctx, j.Operation, j.Generation, local.replica)
		} else {
			result, e = client.Pull(ctx, j.Operation, j.Generation, local.replica)
		}
		if e != nil {
			return nil, e
		}
		return json.Marshal(result)
	}
	gate := v.requestGates[j.Target]
	if j.Kind != "upload" || w.resolve == nil || gate == nil {
		return nil, ErrDenied
	}
	automatic := j.Delegation != ""
	if automatic {
		raw, e := w.planUpload(ctx, v, j, local.replica)
		if e != nil {
			return nil, e
		}
		j.Plan = raw
	}
	dir := filepath.Join(DomainDirectory(w.dir, d.Trust), "uploads", j.Operation)
	var queue *upload.Queue
	e := w.createOrOpen(ctx, dir, func(init bool) error {
		var e error
		relative, err := filepath.Rel(w.dir, dir)
		if err != nil || w.budget == nil {
			return ErrDenied
		}
		queue, e = upload.OpenQueueAt(w.root, w.relative(dir), w.node, upload.Authority{Generation: d.Trust, Planner: d.Planner}, externalQueueLimits, init, w.admission(filepath.ToSlash(relative)))
		return e
	})
	if e != nil {
		return nil, e
	}
	defer queue.Close()
	queue.Guard = w.check
	queue.ObserveHTTPAttempt = func(ctx context.Context, attempt upload.HTTPAttempt) {
		_ = w.writeExternalHTTPAttempt(ctx, attempt)
	}
	if j.MissingRepair == nil {
		queue.Readback = upload.ReadbackOptions{MaxAgeSeconds: d.CloudReadbackMaxAgeSeconds, Store: w.state}
	}
	if e = queue.Enqueue(ctx, local.replica, j.Plan); e != nil {
		return nil, e
	}
	if automatic {
		if e = w.point("upload-queue-admitted"); e != nil {
			return nil, e
		}
		if e = local.replica.ReleasePin(ctx, planningPin(j)); e != nil {
			return nil, e
		}
		if e = w.point("upload-planning-pin-released"); e != nil {
			return nil, e
		}
	}
	e = queue.Run(ctx, local.replica, func(ctx context.Context, profile storage.Profile) (*storage.Backend, error) {
		backend, err := w.resolve(ctx, profile)
		if err != nil {
			return backend, err
		}
		bound, err := backend.WithRequestGate(gate)
		if err != nil && backend != nil {
			backend.Close()
		}
		return bound, err
	}, w.cert.PrivateKey.(ed25519.PrivateKey))
	if e != nil {
		return nil, e
	}
	status, e := queue.Status(ctx)
	if e != nil {
		return nil, e
	}
	job := status.Jobs[j.Operation]
	if job.Phase != "COMPLETE" || job.Receipt == nil {
		return nil, ErrDenied
	}
	return json.Marshal(job.Receipt)
}

func (w *Worker) point(name string) error {
	if w.Fault != nil {
		return w.Fault(name)
	}
	return nil
}
