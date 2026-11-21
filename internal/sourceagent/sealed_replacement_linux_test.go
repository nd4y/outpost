package sourceagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
)

func TestSourceSealedReceiverReplacementAndReclaimsSlot(t *testing.T) {
	const copies = 2
	var third tls.Certificate
	f := newFixtureWithPeer(t, 1800, &third)
	ctx, cancel := context.WithTimeout(t.Context(), 260*time.Second)
	defer cancel()

	type holder struct {
		id, endpoint, directory, replicaPath string
		authority                            []byte
		registry                             *ingress.Registry
		mu                                   sync.RWMutex
		options                              ingress.RegistryOptions
		certificate                          tls.Certificate
		ready                                chan struct{}
		down                                 atomic.Bool
	}
	holders := make([]*holder, 0, copies+1)
	var accepted sync.Map
	var switched atomic.Bool
	var reused, resent atomic.Int64
	var stopReclaim atomic.Bool
	for k, certificate := range []tls.Certificate{f.destination, f.replicaCertificate, third}[:copies+1] {
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		must(t, err)
		h := &holder{certificate: certificate, ready: make(chan struct{}), id: peer.Identity(leaf), directory: filepath.Join(f.base, "route-holder-"+string(rune('a'+k)))}
		grant := f.grant
		grant.Ingress = h.id
		h.authority, err = ingress.SignAuthority(grant, f.ownerSigner)
		must(t, err)
		handler := func(out http.ResponseWriter, req *http.Request) {
			if h.down.Load() {
				http.Error(out, "holder unavailable", http.StatusServiceUnavailable)
				return
			}
			if req.Method == http.MethodPut {
				path := req.URL.Path
				if strings.Contains(path, "/imports/") || strings.Contains(path, "/objects/") {
					id := path[strings.LastIndex(path, "/")+1:]
					if !switched.Load() && k == 0 {
						accepted.Store(id, true)
					} else if switched.Load() {
						if _, old := accepted.Load(id); old && k == copies && strings.Contains(path, "/imports/") {
							reused.Add(1)
						}
						if _, old := accepted.Load(id); old && strings.Contains(path, "/objects/") {
							resent.Add(1)
						}
					}
				}
			}
			<-h.ready
			h.mu.RLock()
			defer h.mu.RUnlock()
			h.registry.ServeHTTP(out, req)
		}
		if k == 0 {
			h.endpoint = f.server.URL
			f.intercept = func(out http.ResponseWriter, req *http.Request) bool { handler(out, req); return true }
		} else {
			server := httptest.NewUnstartedServer(http.HandlerFunc(handler))
			server.TLS, err = peer.AuthenticatedServerTLS(certificate, f.roots, h.id)
			must(t, err)
			server.StartTLS()
			t.Cleanup(server.Close)
			h.endpoint = server.URL
		}
		holders = append(holders, h)
	}
	var targets []string
	for _, h := range holders {
		targets = append(targets, h.id)
		h.replicaPath = filepath.Join(h.directory, "replica")
		must(t, os.MkdirAll(h.replicaPath, 0700))
		replica, err := generation.Open(h.replicaPath, f.grant.Trust, true)
		must(t, err)
		t.Cleanup(func() { replica.Close() })
		staging := &ingress.StagingRoutes{Origins: map[string]string{}, Readers: map[string]bool{}}
		for _, other := range holders {
			if h != other {
				staging.Origins[other.id], staging.Readers[other.id] = other.endpoint, true
			}
		}
		h.options = ingress.RegistryOptions{
			Directory: filepath.Join(h.directory, "ingress"), Owner: f.b.Local.Owner, Authority: h.authority,
			Replica: replica, Certificate: h.certificate, Roots: f.roots, Initialize: true,
			Staging: staging, Limits: sourceFixtureLimits,
		}
		h.registry, err = ingress.OpenRegistry(ctx, h.options)
		must(t, err)
		t.Cleanup(func() { h.registry.Close() })
		if h == holders[1] {
			h.registry.Fault = func(point string) error {
				if point == "capture-reclaim-durable" && stopReclaim.CompareAndSwap(true, false) {
					return errors.New("interrupted old slot cleanup")
				}
				return nil
			}
		}
		close(h.ready)
	}

	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "receiver-route-agent")
	f.b.Profile.MinimumCopies, f.b.Profile.CopyTargets = copies, targets
	f.b.ActiveFailover = true
	selection := func(h *holder) *CompanionIngress {
		file := filepath.Join(h.directory, "source-authority.json")
		must(t, os.WriteFile(file, h.authority, 0600))
		return &CompanionIngress{Endpoint: h.endpoint, AuthorityFile: file}
	}
	f.b.Companion = selection(holders[1])
	f.b.Reserve = selection(holders[2])
	payload := bytes.Repeat([]byte("preserve the bytes already accepted by the surviving receiver"), 512)
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), payload, 0640))
	var err error
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	must(t, f.a.Next(ctx))
	before, err := f.a.Status(ctx)
	must(t, err)
	if before.Phase != "PREPARING" || !slices.Equal(before.Receivers, targets[:copies]) {
		t.Fatal("initial route differs", before)
	}

	failed := holders[1]
	sealed := errors.New("stop after saving the signed catalog")
	f.a.Fault = func(point string) error {
		if point == "source-catalog-durable" {
			return sealed
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, sealed) {
		t.Fatal("capture did not reach the durable catalog", err)
	}
	frozen, err := f.a.Status(ctx)
	must(t, err)
	if frozen.Job == nil || frozen.Job.Phase != "SEALED" {
		t.Fatal("catalog was not durably sealed", frozen)
	}
	original, err := f.a.load()
	must(t, err)
	job, closeJob, err := f.a.openJobMode(ctx, original, true, nil)
	must(t, err)
	transfer, err := job.SealedTransfer(ctx)
	closeJob()
	must(t, err)
	if transfer == nil {
		t.Fatal("catalog is unavailable for replay")
	}
	i, err := f.a.stateIntent(original)
	must(t, err)
	donor, err := f.a.routeReceiver(original, i, holders[0].id)
	must(t, err)
	client, err := ingress.NewClient(donor.endpoint, donor.authority, donor.raw, f.b.Local.Owner, f.a.cert, f.roots, sourceFixtureLimits)
	must(t, err)
	t.Cleanup(client.Close)
	for {
		_, receipt, err := client.FinishStep(ctx, transfer.Catalog)
		must(t, err)
		if receipt != nil {
			break
		}
	}

	failed.down.Store(true)
	crash := errors.New("stop after persisting sealed replacement")
	f.a.Fault = func(point string) error {
		if point == "source-agent-receiver-route-durable" {
			switched.Store(true)
			return crash
		}
		return nil
	}
	if err = f.a.Run(ctx); !errors.Is(err, crash) {
		t.Fatal("did not switch after sealing", err)
	}
	want := []string{holders[0].id, holders[2].id}
	// A routed publication can finish without access to the original bytes.
	must(t, os.Remove(filepath.Join(f.tree, "private.bin")))
	f.reopen(t)
	after, err := f.a.Status(ctx)
	must(t, err)
	if after.Operation != before.Operation || after.Phase != "ACTIVE" || after.Job != nil ||
		after.Pending == nil || after.Pending.Action != "PREPARE_RECEIVER_ROUTE" ||
		!slices.Equal(after.Receivers, want) || !slices.Equal(after.Superseded, before.Receivers) {
		t.Fatal("signed replacement did not survive restart", after)
	}
	for attempt := 0; attempt < 4; attempt++ {
		err = f.a.Run(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !receiverUnavailable(err) {
			t.Fatal("replacement publication failed", err)
		}
		t.Logf("retry publication after bounded transport error: %v", err)
	}
	must(t, err)
	raw, err := f.a.Checkpoint(ctx)
	must(t, err)
	c, err := capture.VerifyCheckpoint(raw, f.grant.Trust)
	must(t, err)
	if c.Receipt.Ingress != want[0] || len(c.Copies) != copies || c.Sequence != 1 || c.Generation != frozen.Job.Generation {
		t.Fatal("incorrect published copies", c)
	}
	if reused.Load() == 0 || resent.Load() != 0 {
		t.Fatal("replacement did not reuse the survivor's accepted objects", reused.Load(), resent.Load())
	}
	for _, h := range holders {
		replica := h.replicaPath
		if h == failed {
			r, err := generation.Open(replica, f.grant.Trust, false)
			must(t, err)
			inventory, err := r.Inventory(ctx)
			must(t, err)
			must(t, r.Close())
			if len(inventory) != 0 {
				t.Fatal("superseded receiver published a catalog", inventory)
			}
			continue
		}
		if !slices.ContainsFunc(c.Copies, func(copy capture.CopyReceipt) bool { return copy.Target == h.id }) {
			t.Fatal("missing independently verified copy", h.id)
		}
		out := filepath.Join(h.directory, "route-restored")
		_, err = generation.RecoverMaterialized(ctx, replica, c.Generation, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, err)
		got, err := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, err)
		if !bytes.Equal(got, payload) {
			t.Fatal("restore differs", h.id)
		}
	}

	failed.down.Store(false)
	must(t, f.a.Run(ctx))
	current, err := f.a.Status(ctx)
	must(t, err)
	if !slices.Equal(current.PendingReclaims, []string{failed.id}) {
		t.Fatal("old slot was cleared before independently verifying the generation", current)
	}
	head, err := f.a.load()
	must(t, err)
	request := head.Reclaims[failed.id]
	cleanup, err := ingress.NewCleanupClient(failed.endpoint, request.Authority, request.Intent, f.b.Local.Owner, f.a.cert, f.roots, sourceFixtureLimits)
	must(t, err)
	defer cleanup.Close()
	invalid := request
	invalid.Grant = bytes.Clone(request.Grant)
	invalid.Grant[0] ^= 1
	if _, err = cleanup.ReclaimStep(ctx, invalid); !errors.Is(err, ingress.ErrDenied) {
		t.Fatal("invalid reclaim proof was accepted", err)
	}
	from, err := generation.Open(holders[0].replicaPath, f.grant.Trust, false)
	must(t, err)
	defer from.Close()
	to, err := generation.Open(failed.replicaPath, f.grant.Trust, false)
	must(t, err)
	defer to.Close()
	id, err := to.Receive(ctx, transfer.Catalog, func(ref generation.Object) ([]byte, error) {
		return from.ReadObject(ctx, c.Generation, ref)
	})
	must(t, err)
	if id != c.Generation {
		t.Fatal("reclaimed replica did not catch up to the same catalog")
	}

	stopReclaim.Store(true)
	must(t, f.a.Run(ctx))
	current, err = f.a.Status(ctx)
	must(t, err)
	if stopReclaim.Load() || len(current.PendingReclaims) != 1 {
		t.Fatal("did not interrupt cleanup after the durable reclaim fence", current)
	}
	failed.mu.Lock()
	err = failed.registry.Close()
	if err == nil {
		failed.options.Initialize = false
		failed.registry, err = ingress.OpenRegistry(ctx, failed.options)
	}
	failed.mu.Unlock()
	must(t, err)
	oldClient, err := ingress.NewClient(failed.endpoint, request.Authority, request.Intent, f.b.Local.Owner, f.a.cert, f.roots, sourceFixtureLimits)
	must(t, err)
	defer oldClient.Close()
	if err = oldClient.Ready(ctx); !errors.Is(err, ingress.ErrConflict) {
		t.Fatal("old intent became writable after receiver restart", err)
	}

	preview := f.intent(t, 2, c.Generation)
	next, err := f.a.intent(preview, true)
	must(t, err)
	_, nextRaw, err := f.a.receiverIntent(next, failed.id, failed.authority)
	must(t, err)
	nextClient, err := ingress.NewClient(failed.endpoint, failed.authority, nextRaw, f.b.Local.Owner, f.a.cert, f.roots, sourceFixtureLimits)
	must(t, err)
	defer nextClient.Close()
	if err = nextClient.Ready(ctx); !errors.Is(err, ingress.ErrConflict) {
		t.Fatal("new admission overtook interrupted cleanup", err)
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
	current, err = f.a.Status(ctx)
	must(t, err)
	if len(current.PendingReclaims) != 0 {
		t.Fatal("reclaim did not resume", current)
	}

	must(t, nextClient.Ready(ctx))
	must(t, nextClient.Begin(ctx))
	clean, err := cleanup.ReclaimStep(ctx, request)
	must(t, err)
	if !clean {
		t.Fatal("stale cleanup request did not confirm the superseded slot")
	}
	must(t, nextClient.Ready(ctx))
}
