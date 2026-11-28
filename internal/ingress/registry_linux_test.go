package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

type registryFixture struct {
	*fixture
	registry   *Registry
	options    RegistryOptions
	server     *httptest.Server
	client     *Client
	sourceCert tls.Certificate
	ca         *testCA
}

func registryNetwork(t *testing.T) *registryFixture {
	t.Helper()
	ca := newCA(t)
	source, target := ca.node(t), ca.node(t)
	f := setupIDs(t, certID(t, source), certID(t, target))
	must(t, f.source.Close())
	f.source = nil
	must(t, f.session.Close())
	f.session = nil
	o := RegistryOptions{Directory: filepath.Join(f.base, "registry"), Authority: f.options.Authority, Owner: f.options.Owner, Replica: f.options.Replica, Certificate: target, Roots: ca.roots, Limits: httpLimits, Initialize: true}
	g, e := OpenRegistry(context.Background(), o)
	must(t, e)
	x := &registryFixture{fixture: f, registry: g, options: o, sourceCert: source, ca: ca}
	t.Cleanup(func() {
		if x.registry != nil {
			x.registry.Close()
		}
	})
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { x.registry.ServeHTTP(w, r) }))
	s.TLS, e = peer.AuthenticatedServerTLS(target, ca.roots, f.intent.Ingress)
	must(t, e)
	s.StartTLS()
	x.server = s
	t.Cleanup(s.Close)
	x.client, e = NewClient(s.URL, o.Authority, f.options.Intent, o.Owner, source, ca.roots, httpLimits)
	must(t, e)
	t.Cleanup(x.client.Close)
	f.source, e = filekit.OpenStreamingStore(filepath.Join(f.base, "source-cache"), f.owner, false, x.client)
	must(t, e)
	return x
}
func (x *registryFixture) reopen(t *testing.T) {
	t.Helper()
	must(t, x.registry.Close())
	x.registry = nil
	x.options.Initialize = false
	var e error
	x.registry, e = OpenRegistry(context.Background(), x.options)
	must(t, e)
}
func (x *registryFixture) complete(t *testing.T) (Receipt, string, string) {
	t.Helper()
	ctx := context.Background()
	must(t, x.client.Begin(ctx))
	v, e := x.source.Backup(ctx, x.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, e)
	raw, roots := x.catalog(t, []string{v.Version})
	for id, b := range roots {
		_, e = x.client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	_, receipt, e := x.client.FinishStep(ctx, raw)
	must(t, e)
	if receipt == nil {
		t.Fatal("no receipt")
	}
	return *receipt, v.File, v.Version
}
func (x *registryFixture) next(t *testing.T, prior Receipt) []byte {
	i := x.intent
	i.Sequence++
	i.Parent = prior.Generation
	i.Operation = storage.Hash([]byte(prior.Operation + "next"))
	i.SnapshotUnix = time.Now().Unix()
	raw, e := SignIntent(i, x.options.Authority, x.options.Owner, x.writer, time.Now())
	must(t, e)
	x.intent = i
	return raw
}
func TestRegistryFencesAdmissionAndRecyclesOnlyAcknowledgedSlot(t *testing.T) {
	x := registryNetwork(t)
	ctx := context.Background()
	if _, e := OpenRegistry(ctx, x.options); !errors.Is(e, ErrConflict) {
		t.Fatal("second process lease admitted", e)
	}
	first, _, _ := x.complete(t)
	next := x.next(t, first)
	if _, e := x.registry.begin(ctx, next); !errors.Is(e, ErrConflict) {
		t.Fatal("unacknowledged capture displaced", e)
	}
	ack, e := x.client.AcknowledgeStep(ctx, first)
	must(t, e)
	if !ack.Clean {
		t.Fatal("not clean")
	}
	x.registry.Fault = func(point string) error {
		if point == "capture-intent-durable" {
			return errors.New("lost fence reply")
		}
		return nil
	}
	if _, e = x.registry.begin(ctx, next); e == nil {
		t.Fatal("fault absent")
	}
	x.reopen(t)
	if e = x.client.Begin(ctx); e == nil {
		t.Fatal("old intent resurrected")
	}
	_, e = x.registry.begin(ctx, next)
	must(t, e)
	if x.registry.session.intent.Sequence != 2 {
		t.Fatal("new slot absent")
	}
	entries, e := os.ReadDir(filepath.Join(x.options.Directory, "current/objects"))
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("old stage carried forward")
	}
	status, e := x.options.Replica.Status(ctx)
	must(t, e)
	if status.LatestComplete != first.Generation || len(status.Complete) != 1 {
		t.Fatal("slot reuse retired data", status)
	}
	must(t, x.options.Replica.VerifyComplete(ctx, first.Generation))
}
func TestRegistryRestartResumesActiveIntentAndRejectsChangedGrant(t *testing.T) {
	x := registryNetwork(t)
	ctx := context.Background()
	must(t, x.client.Begin(ctx))
	b := []byte("accepted before restart")
	ref := filekit.Object{ID: storage.Hash(b), Bytes: len(b)}
	_, e := x.client.Write(ctx, ref, b)
	must(t, e)
	x.reopen(t)
	must(t, x.client.Begin(ctx))
	got, e := x.client.Read(ctx, ref)
	must(t, e)
	if string(got) != string(b) {
		t.Fatal("staged object lost")
	}
	must(t, x.registry.Close())
	x.registry = nil
	a := x.authority
	a.Revision++
	x.options.Authority, e = SignAuthority(a, x.control)
	must(t, e)
	if other, e := OpenRegistry(ctx, x.options); e == nil {
		other.Close()
		t.Fatal("changed grant silently rebound active data")
	}
}
func TestRegistrySlotReplacementLostReplyKeepsFence(t *testing.T) {
	x := registryNetwork(t)
	ctx := context.Background()
	first, _, _ := x.complete(t)
	_, e := x.client.AcknowledgeStep(ctx, first)
	must(t, e)
	next := x.next(t, first)
	x.registry.Fault = func(point string) error {
		if point == "capture-slot-replaced" {
			return errors.New("slot reply lost")
		}
		return nil
	}
	if _, e = x.registry.begin(ctx, next); e == nil {
		t.Fatal("fault absent")
	}
	x.reopen(t)
	_, e = x.registry.begin(ctx, next)
	must(t, e)
	if x.registry.session.intent.Sequence != 2 {
		t.Fatal("fence lost")
	}
	if e = x.client.Begin(ctx); e == nil {
		t.Fatal("replayed prior operation")
	}
}

func TestRegistryRejectsClockRollbackAcrossSlotReplacement(t *testing.T) {
	x := registryNetwork(t)
	ctx := context.Background()
	first, _, _ := x.complete(t)
	_, e := x.client.AcknowledgeStep(ctx, first)
	must(t, e)
	next := x.next(t, first)
	x.registry.session.state.LastObserved = time.Now().Add(time.Minute).Unix()
	must(t, x.registry.session.save())
	if _, e = x.registry.begin(ctx, next); !errors.Is(e, ErrConflict) {
		t.Fatal("slot replacement bypassed clock guard", e)
	}
	x.registry.state.ObservedUnix = time.Now().Add(time.Minute).Unix()
	must(t, x.registry.save())
	must(t, x.registry.Close())
	x.registry = nil
	x.options.Initialize = false
	if g, e := OpenRegistry(ctx, x.options); !errors.Is(e, ErrConflict) {
		if g != nil {
			g.Close()
		}
		t.Fatal("restart bypassed clock guard", e)
	}
}
