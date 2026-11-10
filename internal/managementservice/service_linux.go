// Package managementservice installs the private operator plane runtime.
// It never loads source or recovery data keys or starts a backup worker.
package managementservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

const Format = "outpost-management-service-1"
const maxProfile = 1 << 20

type Profile struct {
	Format              string                 `json:"format"`
	Revision            uint64                 `json:"revision"`
	Local               worker.Bootstrap       `json:"local"`
	Listen              string                 `json:"listen"`
	Origin              string                 `json:"origin"`
	Principals          []management.Principal `json:"principals"`
	Relays              map[string][]string    `json:"relays,omitempty"`
	Limits              diskbudget.Limits      `json:"limits"`
	Concurrency         int                    `json:"concurrency"`
	TimeoutMillis       int                    `json:"timeoutMillis"`
	ReportMaxAgeSeconds int                    `json:"reportMaxAgeSeconds"`
	ReconcileSeconds    int                    `json:"reconcileSeconds"`
	RegistryJournalCopy bool                   `json:"registryJournalCopy,omitempty"`
}

func Load(path string) (Profile, error) {
	var p Profile
	raw, e := worker.ReadPrivate(path, maxProfile)
	if e != nil {
		return p, e
	}
	e = worker.DecodeInput(raw, &p, maxProfile)
	return p, e
}
func (p Profile) options() management.HTTPOptions {
	return management.HTTPOptions{Principals: p.Principals, Relays: p.Relays, Origin: p.Origin, Concurrency: p.Concurrency, Timeout: time.Duration(p.TimeoutMillis) * time.Millisecond, ReportMaxAge: time.Duration(p.ReportMaxAgeSeconds) * time.Second}
}
func (p Profile) digest() string { raw, _ := json.Marshal(p); return storage.Hash(raw) }

type serviceState struct {
	Format        string            `json:"format"`
	Service       string            `json:"service"`
	Owner         ed25519.PublicKey `json:"owner"`
	Revision      uint64            `json:"revision"`
	ProfileDigest string            `json:"profileDigest"`
	ObservedUnix  int64             `json:"observedUnix"`
	Signature     []byte            `json:"signature,omitempty"`
}
type Service struct {
	p            Profile
	root         *os.Root
	budget       *diskbudget.Budget
	state, lease *statefile.Store
	registry     *management.Registry
	tls          *tls.Config
	signer       ed25519.PrivateKey
	// SnapshotFault is a local process-interruption hook, never profile input.
	SnapshotFault func(string) error
}

func Open(ctx context.Context, p Profile, initialize bool) (*Service, error) {
	return open(ctx, p, initialize, false)
}

func RecoverRegistry(ctx context.Context, p Profile) (Status, error) {
	if !p.RegistryJournalCopy {
		return Status{}, management.ErrDenied
	}
	s, e := open(ctx, p, false, true)
	if e != nil {
		return Status{}, e
	}
	defer s.Close()
	return s.Status(ctx)
}

func open(ctx context.Context, p Profile, initialize, recoverJournal bool) (*Service, error) {
	if p.Format != Format || p.Revision == 0 || p.Revision > management.MaxSafeInteger || p.Local.Format != worker.BootstrapFormat || p.Local.Volume.Scope != p.Local.Node || !storage.ID(p.Local.Node) || len(p.Local.Owner) != 32 || !filepath.IsAbs(p.Local.Directory) || p.Local.ControlEndpoint != "" || p.Local.ControlIdentity != "" || p.Local.Listen != "" || p.Local.StorageCAFile != "" || len(p.Local.Credentials) != 0 || p.ReconcileSeconds < 1 || p.ReconcileSeconds > 3600 {
		return nil, management.ErrInvalid
	}
	if p.TimeoutMillis < 100 || p.TimeoutMillis > 10000 || p.ReportMaxAgeSeconds < 1 || p.ReportMaxAgeSeconds > 86400 || p.Limits.Validate() != nil {
		return nil, management.ErrInvalid
	}
	host, port, e := net.SplitHostPort(p.Listen)
	if e != nil || net.ParseIP(host) == nil {
		return nil, management.ErrInvalid
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return nil, management.ErrInvalid
	}
	// Deep copy the admitted local configuration before another goroutine runs.
	raw, _ := json.Marshal(p)
	if len(raw) > maxProfile {
		return nil, management.ErrInvalid
	}
	// Unmarshal into a zero value: decoding into p can reuse caller-owned
	// slices/maps, racing an already running service opened from that profile.
	var admitted Profile
	if e = json.Unmarshal(raw, &admitted); e != nil {
		return nil, e
	}
	p = admitted
	cert, roots, e := p.Local.TLS()
	if e != nil {
		return nil, e
	}
	origin, e := url.Parse(p.Origin)
	if e != nil {
		return nil, management.ErrInvalid
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	intermediates := x509.NewCertPool()
	for _, raw := range cert.Certificate[1:] {
		c, e := x509.ParseCertificate(raw)
		if e != nil {
			return nil, e
		}
		intermediates.AddCert(c)
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: origin.Hostname(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); e != nil {
		return nil, management.ErrDenied
	}
	signer, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(signer) != 64 || bytes.Equal(p.Local.Owner, signer.Public().(ed25519.PublicKey)) {
		return nil, management.ErrInvalid
	}
	tlsConfig, e := peer.AuthenticatedServerTLS(cert, roots, p.Local.Node)
	if e != nil {
		return nil, e
	}
	// Handler validation has no side effects and precedes directory creation.
	if _, e = management.Handler(new(management.Registry), p.options()); e != nil {
		return nil, e
	}
	s := &Service{p: p, tls: tlsConfig, signer: signer}
	s.root, e = p.Local.Volume.Open(ctx, p.Local.Directory, initialize)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Service, error) { s.Close(); return nil, e }
	s.lease, e = statefile.OpenAt(s.root, "lease", 4096, initialize)
	if e != nil {
		return fail(e)
	}
	s.budget, e = diskbudget.OpenAt(s.root, ctx, ".", p.Limits, initialize)
	if e != nil {
		return fail(e)
	}
	s.state, e = statefile.OpenAt(s.root, "service", 65536, initialize)
	if e != nil {
		return fail(e)
	}
	s.state.Admit = s.admission("service")
	options := management.Options{Root: s.root, Directory: "registry", Owner: p.Local.Owner, Signer: s.signer, Initialize: initialize, JournalCopy: p.RegistryJournalCopy, Guard: s.guard, Admission: s.admission("registry")}
	if initialize {
		e = s.lease.WithLock(ctx, func() error {
			if _, e := s.state.Read("profile.json"); !errors.Is(e, os.ErrNotExist) {
				return management.ErrConflict
			}
			s.registry, e = management.Open(options)
			if e != nil {
				return e
			}
			return s.saveProfile(serviceState{})
		})
	} else if recoverJournal {
		e = s.lease.WithLock(ctx, func() error {
			if _, e := s.loadProfile(true); e != nil {
				return e
			}
			var repairErr error
			s.registry, repairErr = management.RecoverRegistry(ctx, options)
			return repairErr
		})
	} else {
		if _, e = s.loadProfile(false); e == nil {
			s.registry, e = management.Open(options)
		}
	}
	if e != nil {
		return fail(e)
	}
	return s, nil
}
func (s *Service) Close() error {
	var e error
	if s.registry != nil {
		e = errors.Join(e, s.registry.Close())
	}
	for _, store := range []*statefile.Store{s.state, s.lease} {
		if store != nil {
			e = errors.Join(e, store.Close())
		}
	}
	if s.budget != nil {
		e = errors.Join(e, s.budget.Close())
	}
	if s.root != nil {
		e = errors.Join(e, s.root.Close())
	}
	return e
}
func (s *Service) guard(ctx context.Context) error {
	return s.p.Local.Volume.CheckHandle(ctx, s.p.Local.Directory, s.root)
}
func (s *Service) admission(prefix string) statefile.Admission {
	return func(name string, size int) (func(bool) error, error) {
		if e := s.guard(context.Background()); e != nil {
			return nil, e
		}
		done, e := s.budget.Admission(prefix)(name, size)
		if e != nil {
			return nil, e
		}
		return func(written bool) error { return errors.Join(done(written), s.guard(context.Background())) }, nil
	}
}
func (s *Service) loadProfile(exact bool) (serviceState, error) {
	var value serviceState
	if e := s.guard(context.Background()); e != nil {
		return value, e
	}
	raw, e := s.state.Read("profile.json")
	if e != nil {
		return value, e
	}
	if storage.Decode(raw, &value, 65536) != nil || value.Format != Format || value.Service != s.p.Local.Node || !bytes.Equal(value.Owner, s.p.Local.Owner) || value.Revision == 0 || value.Revision > management.MaxSafeInteger || !storage.ID(value.ProfileDigest) || value.ObservedUnix < 1 || value.ObservedUnix > time.Now().Unix() {
		return value, management.ErrInvalid
	}
	sig := value.Signature
	value.Signature = nil
	unsigned, _ := json.Marshal(value)
	value.Signature = sig
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(raw, canonical) || !ed25519.Verify(s.signer.Public().(ed25519.PublicKey), append([]byte(Format+"\x00"), unsigned...), sig) {
		return value, management.ErrInvalid
	}
	if exact && (value.Revision != s.p.Revision || value.ProfileDigest != s.p.digest()) {
		return value, management.ErrConflict
	}
	return value, nil
}
func (s *Service) saveProfile(old serviceState) error {
	if s.p.Revision <= old.Revision || time.Now().Unix() < old.ObservedUnix {
		return management.ErrConflict
	}
	value := serviceState{Format: Format, Service: s.p.Local.Node, Owner: s.p.Local.Owner, Revision: s.p.Revision, ProfileDigest: s.p.digest(), ObservedUnix: time.Now().Unix()}
	raw, _ := json.Marshal(value)
	value.Signature = ed25519.Sign(s.signer, append([]byte(Format+"\x00"), raw...))
	raw, _ = json.Marshal(value)
	if e := s.state.Write("profile.json", raw); e != nil {
		return e
	}
	return s.guard(context.Background())
}

// ApplyProfile requires the execution lease. A running service must be stopped
// before changing its local ACL/listener. An exact replay is idempotent.
func (s *Service) ApplyProfile(ctx context.Context) error {
	return s.lease.WithLock(ctx, func() error {
		old, e := s.loadProfile(false)
		if e != nil {
			return e
		}
		if old.Revision == s.p.Revision && old.ProfileDigest == s.p.digest() {
			return nil
		}
		return s.saveProfile(old)
	})
}

type Status struct {
	Format          string           `json:"format"`
	Service         string           `json:"service"`
	ProfileRevision uint64           `json:"profileRevision"`
	ProfileDigest   string           `json:"profileDigest"`
	ObservedUnix    int64            `json:"observedUnix"`
	Space           diskbudget.State `json:"space"`
}

func (s *Service) Status(ctx context.Context) (Status, error) {
	state, e := s.loadProfile(true)
	if e != nil {
		return Status{}, e
	}
	space, e := s.budget.Status(ctx)
	if e != nil {
		return Status{}, e
	}
	return Status{Format: "outpost-management-service-status-1", Service: state.Service, ProfileRevision: state.Revision, ProfileDigest: state.ProfileDigest, ObservedUnix: time.Now().Unix(), Space: space}, s.guard(ctx)
}
func (s *Service) Reconcile(ctx context.Context) (management.ReconcileResult, error) {
	var out management.ReconcileResult
	e := s.lease.WithLock(ctx, func() error {
		if _, e := s.loadProfile(true); e != nil {
			return e
		}
		if e := s.budget.Reconcile(ctx, s.p.Limits); e != nil {
			return e
		}
		var e error
		out, e = s.registry.Reconcile(ctx, s.p.Principals, 0, 64)
		return e
	})
	return out, e
}
func (s *Service) Run(ctx context.Context) error {
	return s.lease.WithLock(ctx, func() error {
		if _, e := s.loadProfile(true); e != nil {
			return e
		}
		if e := s.budget.Reconcile(ctx, s.p.Limits); e != nil {
			return e
		}
		handler, e := management.Handler(s.registry, s.p.options())
		if e != nil {
			return e
		}
		listener, e := net.Listen("tcp", s.p.Listen)
		if e != nil {
			return e
		}
		defer listener.Close()
		run, cancel := context.WithCancelCause(ctx)
		defer cancel(context.Canceled)
		requests := &drainingHandler{handler: handler}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: time.Duration(s.p.TimeoutMillis)*time.Millisecond + time.Second, WriteTimeout: time.Duration(s.p.TimeoutMillis)*time.Millisecond + time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: s.tls, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return run }}
		server.Handler = requests
		done := make(chan error, 1)
		limited := &limitedListener{Listener: listener, slots: make(chan struct{}, s.p.Concurrency*8+8)}
		go func() { done <- server.Serve(tls.NewListener(limited, s.tls)) }()
		monitor := time.NewTicker(100 * time.Millisecond)
		defer monitor.Stop()
		reconcile := time.NewTimer(0)
		defer reconcile.Stop()
		var cursor uint64
		var result error
	loop:
		for {
			select {
			case <-run.Done():
				result = context.Cause(run)
				break loop
			case e := <-done:
				if !errors.Is(e, http.ErrServerClosed) {
					result = e
				}
				done = nil
				break loop
			case <-monitor.C:
				if _, e := s.loadProfile(true); e != nil {
					result = e
					break loop
				}
			case <-reconcile.C:
				bounded, stop := context.WithTimeout(run, time.Duration(s.p.TimeoutMillis)*time.Millisecond)
				page, e := s.registry.Reconcile(bounded, s.p.Principals, cursor, 64)
				stop()
				if e != nil {
					if run.Err() != nil {
						result = context.Cause(run)
						if e != run.Err() && e != context.DeadlineExceeded {
							result = e
						}
						break loop
					}
					if !errors.Is(e, context.DeadlineExceeded) {
						result = e
						break loop
					}
				} else {
					cursor = page.NextSequence
				}
				reconcile.Reset(time.Duration(s.p.ReconcileSeconds) * time.Second)
			}
		}
		cancel(result)
		requests.drain()
		shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		e = server.Shutdown(shutdown)
		if e != nil {
			closed := server.Close()
			if e == shutdown.Err() {
				// A silent TLS client can outlive graceful draining. Closing it
				// is part of normal bounded stop, not a failed backup operation.
				e = closed
			} else {
				e = errors.Join(e, closed)
			}
		}
		requests.active.Wait()
		if done != nil {
			<-done
		}
		if ctx.Err() != nil && result == ctx.Err() {
			result = nil
		}
		return errors.Join(result, e)
	})
}
