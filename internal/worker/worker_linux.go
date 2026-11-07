package worker

import (
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
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/upload"
)

type Options struct {
	Directory   string
	Node        string
	Owner       ed25519.PublicKey
	Certificate tls.Certificate
	Roots       *x509.CertPool
	Initialize  bool
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
type view struct {
	cfg      control.Config
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	err      error
	requests sync.WaitGroup
	domains  map[string]*domainState
}
type Worker struct {
	budgetMu     sync.Mutex
	dir, node    string
	cert         tls.Certificate
	roots        *x509.CertPool
	cache        *control.Cache
	state, lease *statefile.Store
	fetcher      *control.Fetcher
	resolve      func(context.Context, storage.Profile) (*storage.Backend, error)
	mu           sync.Mutex
	active       *view
	budget       *diskbudget.Budget
	owner        ed25519.PublicKey
}

func Open(o Options) (*Worker, error) {
	if !filepath.IsAbs(o.Directory) || !storage.ID(o.Node) || len(o.Owner) != 32 || len(o.Certificate.Certificate) == 0 || o.Roots == nil {
		return nil, ErrDenied
	}
	leaf, e := x509.ParseCertificate(o.Certificate.Certificate[0])
	if e != nil || peer.Identity(leaf) != o.Node {
		return nil, ErrDenied
	}
	if _, ok := o.Certificate.PrivateKey.(ed25519.PrivateKey); !ok {
		return nil, ErrDenied
	}
	w := &Worker{dir: o.Directory, node: o.Node, cert: o.Certificate, roots: o.Roots.Clone(), fetcher: o.Fetcher, resolve: o.Resolve, owner: append(ed25519.PublicKey(nil), o.Owner...)}
	if o.Initialize {
		if _, e = os.Lstat(o.Directory); e == nil {
			return nil, ErrDenied
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		if e = os.MkdirAll(o.Directory, 0700); e != nil {
			return nil, e
		}
	}
	w.state, e = statefile.Open(filepath.Join(o.Directory, "state"), 32<<20, o.Initialize)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Worker, error) { w.Close(); return nil, e }
	if e = initState(w.state, w.node, o.Initialize); e != nil {
		return fail(e)
	}
	if _, e = w.Status(context.Background()); e != nil {
		return fail(e)
	}
	w.lease, e = statefile.Open(filepath.Join(o.Directory, "lease"), 4096, o.Initialize)
	if e != nil {
		return fail(e)
	}
	w.cache, e = control.OpenCache(filepath.Join(o.Directory, "control"), o.Node, o.Owner, o.Initialize)
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
	return e
}
func (w *Worker) Accept(ctx context.Context, raw []byte) error {
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
		b, e := diskbudget.Open(ctx, w.dir, limits, initialize)
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
	if e := w.state.SetAdmission(ctx, w.budget.Admission("state")); e != nil {
		return nil, e
	}
	if e := w.cache.SetAdmission(ctx, w.budget.Admission("control")); e != nil {
		return nil, e
	}
	return w.budget, nil
}
func DomainDirectory(root string, t generation.Trust) string {
	return filepath.Join(root, "domains", t.Domain, t.Repository, strconv.FormatUint(t.Epoch, 10))
}
func createOrOpen(dir string, open func(bool) error) error {
	e := os.MkdirAll(filepath.Dir(dir), 0700)
	if e != nil {
		return e
	}
	e = os.Mkdir(dir, 0700)
	if e == nil {
		return open(true)
	}
	if !errors.Is(e, os.ErrExist) {
		return e
	}
	return open(false)
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
		p.RequiredRevision = job.PeerRevision
		n, _ := c.NodeByID(job.Peer)
		p.Peers[job.Peer] = peer.Grant{Class: n.Class, Push: job.Kind == "push", Pull: true, ExpiresUnix: c.ExpiresUnix}
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
	return p
}
func (w *Worker) start(ctx context.Context, c control.Config) (*view, error) {
	v := &view{cfg: c, done: make(chan struct{}), domains: map[string]*domainState{}}
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
		e := createOrOpen(filepath.Join(dir, "replica"), func(init bool) error {
			var e error
			local.replica, e = generation.Open(filepath.Join(dir, "replica"), d.Trust, init)
			return e
		})
		if e != nil {
			return fail(e)
		}
		e = createOrOpen(filepath.Join(dir, "peer"), func(init bool) error {
			var e error
			local.journal, e = peer.OpenJournal(filepath.Join(dir, "peer"), w.node, d.Trust, init)
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
	if e := w.state.SetAdmission(ctx, w.budget.Admission("state")); e != nil {
		return fail(e)
	}
	if e := w.cache.SetAdmission(ctx, w.budget.Admission("control")); e != nil {
		return fail(e)
	}
	for id, local := range v.domains {
		d, _ := c.DomainByID(id)
		relative, e := filepath.Rel(w.dir, DomainDirectory(w.dir, d.Trust))
		if e != nil {
			return fail(e)
		}
		local.replica.Admit = w.budget.Admission(filepath.ToSlash(filepath.Join(relative, "replica")))
		local.journal.Admit = w.budget.Admission(filepath.ToSlash(filepath.Join(relative, "peer")))
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
		e = createOrOpen(dir, func(init bool) error {
			var e error
			local.ingress, e = ingress.OpenRegistry(v.ctx, ingress.RegistryOptions{Directory: dir, Authority: raw, Owner: w.owner, Replica: local.replica, Certificate: w.cert, Roots: w.roots, Initialize: init, Limits: peer.Limits{Concurrency: c.Limits.Parallel, Timeout: time.Duration(c.Limits.AttemptMillis) * time.Millisecond, Attempts: 2}, Admission: func(prefix string) statefile.Admission {
				return w.budget.Admission(filepath.ToSlash(filepath.Join(relative, prefix)))
			}, RemoveObject: func(ctx context.Context, name string, size int64) error {
				return w.budget.Remove(ctx, filepath.ToSlash(filepath.Join(relative, "current/objects", name)), size)
			}})
			return e
		})
		if e != nil {
			return fail(e)
		}
	}
	if e := w.admit(ctx, c); e != nil {
		return fail(e)
	}
	w.mu.Lock()
	w.active = v
	w.mu.Unlock()
	go func() { v.err = w.jobs(v); close(v.done) }()
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
func (w *Worker) Run(ctx context.Context) error {
	e := w.lease.WithLock(ctx, func() (runErr error) {
		var active *view
		defer func() {
			if ctx.Err() != nil && (runErr == context.Canceled || runErr == context.DeadlineExceeded) {
				runErr = nil
			}
			if stopErr := w.stop(active); stopErr != nil {
				runErr = errors.Join(runErr, stopErr)
			}
		}()
		poll := time.Second
		stop := func() error { old := active; active = nil; return w.stop(old) }
		for {
			if ctx.Err() != nil {
				return nil
			}
			if w.fetcher != nil {
				fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				raw, e := w.fetcher.Fetch(fetchCtx)
				cancel()
				if e == nil {
					_ = w.Accept(ctx, raw)
				}
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
			case <-timer.C:
			}
		}
	})
	if e == ctx.Err() && ctx.Err() != nil {
		return nil
	}
	return e
}

// ServeHTTP delegates only exact signed inbound jobs. It cannot be used as a
// generic authenticated object server or as an implicit reverse route.
func (w *Worker) ServeHTTP(out http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		http.Error(out, "denied", 403)
		return
	}
	parts := strings.Split(r.URL.Path, "/")
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
		if j.Peer == w.node && j.Executor == remote && j.Domain == parts[2] && j.Generation == parts[4] && j.Operation == r.Header.Get("Outpost-Operation") && j.Kind == r.Header.Get("Outpost-Mode") {
			allowed = true
			break
		}
	}
	if !allowed || d == nil || d.handler == nil {
		w.mu.Unlock()
		http.Error(out, "denied", 403)
		return
	}
	v.requests.Add(1)
	w.mu.Unlock()
	defer v.requests.Done()
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(v.ctx, cancel)
	defer stop()
	defer cancel()
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
		if j.Kind == "push" {
			result, e = client.Push(ctx, j.Operation, j.Generation, local.replica)
		} else {
			result, e = client.Pull(ctx, j.Operation, j.Generation, local.replica)
		}
		if e != nil {
			return nil, e
		}
		return json.Marshal(result)
	}
	if j.Kind != "upload" || w.resolve == nil {
		return nil, ErrDenied
	}
	dir := filepath.Join(DomainDirectory(w.dir, d.Trust), "uploads", j.Operation)
	var queue *upload.Queue
	e := createOrOpen(dir, func(init bool) error {
		var e error
		relative, err := filepath.Rel(w.dir, dir)
		if err != nil || w.budget == nil {
			return ErrDenied
		}
		queue, e = upload.OpenQueueAdmitted(dir, w.node, upload.Authority{Generation: d.Trust, Planner: d.Planner}, upload.QueueLimits{MaxJobs: 1, Parallel: 1, AttemptMillis: 300000, RetryBaseMillis: 1000, RetryMaxMillis: 60000}, init, w.budget.Admission(filepath.ToSlash(relative)))
		return e
	})
	if e != nil {
		return nil, e
	}
	defer queue.Close()
	if e = queue.Enqueue(ctx, local.replica, j.Plan); e != nil {
		return nil, e
	}
	e = queue.Run(ctx, local.replica, w.resolve, w.cert.PrivateKey.(ed25519.PrivateKey))
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
