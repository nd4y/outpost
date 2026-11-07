package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
)

func (f *fixture) rules() (control.Replication, control.Replication) {
	return control.Replication{Domain: f.domain.Trust.Domain, From: f.nodes[0].node, To: f.nodes[1].node, Mode: "push", Epoch: 1, PeerRevision: 1}, control.Replication{Domain: f.domain.Trust.Domain, From: f.nodes[1].node, To: f.nodes[2].node, Mode: "pull", Epoch: 1, PeerRevision: 1}
}
func (f *fixture) replicationConfig(t *testing.T, index int, revision uint64, rules ...control.Replication) control.Config {
	t.Helper()
	c := f.cfg
	c.Node = f.nodes[index].node
	c.Revision = revision
	c.Domains = []control.Domain{f.domain}
	c.Replication = rules
	c.Jobs = nil
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, f.nodes[index].Accept(context.Background(), raw))
	return c
}

func TestAutonomousDiscoveryReplicatesRetainedHistoryThroughOutboundOnlyNode(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	push, pull := f.rules()
	ctx := context.Background()
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	f.replicationConfig(t, 2, 1, pull)
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	firstPush := push.Job(f.domain.Trust, f.generation)
	wait(t, func() bool { return complete(f.nodes[0], firstPush.Operation) })
	store, e := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, false)
	must(t, e)
	changed := bytes.Repeat([]byte("autonomous next generation"), 4096)
	input := filepath.Join(f.base, "next-input")
	must(t, os.WriteFile(input, changed, 0640))
	version, e := store.Backup(ctx, input, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, e)
	f.nodes[0].mu.Lock()
	replica := f.nodes[0].active.domains[f.domain.Trust.Domain].replica
	f.nodes[0].mu.Unlock()
	second, e := generation.Seal(ctx, store, []string{version.Version}, replica, generation.Catalog{Format: generation.Format, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 2, Parent: f.generation, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, e)
	must(t, store.Close())
	wait(t, func() bool { return complete(f.nodes[0], push.Job(f.domain.Trust, second).Operation) })
	stopA()
	// No per-generation jobs or new control configuration were published.
	stopC := start(t, f.nodes[2])
	firstPull, secondPull := pull.Job(f.domain.Trust, f.generation), pull.Job(f.domain.Trust, second)
	wait(t, func() bool {
		return complete(f.nodes[2], firstPull.Operation) && complete(f.nodes[2], secondPull.Operation)
	})
	observed, e := f.nodes[2].DiscoveryStatus(ctx)
	must(t, e)
	if observed.Revision != 1 || observed.Routes[pull.ID(f.domain.Trust)].Phase != "DISCOVERED" || observed.Routes[pull.ID(f.domain.Trust)].Generations != 2 {
		t.Fatal("wrong discovery observation", observed)
	}
	prior, e := f.nodes[2].Status(ctx)
	must(t, e)
	stopC()
	stopB()
	server.Close()
	reopened, e := Open(Options{Directory: f.nodes[2].dir, Node: f.nodes[2].node, Owner: f.owner.Public().(ed25519.PublicKey), Certificate: f.nodes[2].cert, Roots: f.ca.pool})
	must(t, e)
	defer reopened.Close()
	stop := start(t, reopened)
	wait(t, func() bool { reopened.mu.Lock(); defer reopened.mu.Unlock(); return reopened.active != nil })
	after, e := reopened.Status(ctx)
	must(t, e)
	if !bytes.Equal(after.Jobs[firstPull.Operation].Receipt, prior.Jobs[firstPull.Operation].Receipt) || !bytes.Equal(after.Jobs[secondPull.Operation].Receipt, prior.Jobs[secondPull.Operation].Receipt) {
		t.Fatal("offline restart changed verified receipts")
	}
	stop()
	must(t, os.RemoveAll(filepath.Join(f.base, "source-kit")))
	must(t, os.Remove(input))
	must(t, os.Remove(filepath.Join(f.base, "input")))
	for name, item := range map[string]struct {
		id      string
		content []byte
	}{"old": {f.generation, f.content}, "new": {second, changed}} {
		out := filepath.Join(f.base, "recovered-"+name)
		_, e := generation.RecoverMaterialized(ctx, filepath.Join(DomainDirectory(reopened.dir, f.domain.Trust), "replica"), item.id, f.domain.Trust, f.dataOwner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
		must(t, e)
		if !bytes.Equal(got, item.content) {
			t.Fatal("wrong autonomous independent recovery", name)
		}
	}
}

func TestInventoryRequiresCurrentPullRuleAndRejectsReverseMetadataRoute(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	push, pull := f.rules()
	ctx := context.Background()
	f.replicationConfig(t, 1, 1, push, pull)
	stop := start(t, f.nodes[1])
	defer stop()
	wait(t, func() bool { f.nodes[1].mu.Lock(); defer f.nodes[1].mu.Unlock(); return f.nodes[1].active != nil })
	request := func(node *Worker, rule control.Replication, suffix string) int {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{node.cert}}}}
		defer client.CloseIdleConnections()
		r, e := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/"+f.domain.Trust.Domain+"/inventory"+suffix, nil)
		must(t, e)
		r.Header.Set("Outpost-Replication", rule.ID(f.domain.Trust))
		r.Header.Set("Outpost-Required-Revision", "1")
		res, e := client.Do(r)
		must(t, e)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	if code := request(f.nodes[0], pull, ""); code != 403 {
		t.Fatal("push sender received reverse inventory", code)
	}
	if code := request(f.nodes[2], pull, "?other=domain"); code != 403 {
		t.Fatal("query accepted", code)
	}
	if code := request(f.nodes[2], pull, ""); code != 200 {
		t.Fatal("authorized inventory denied", code)
	}
	f.replicationConfig(t, 1, 2, push)
	wait(t, func() bool {
		f.nodes[1].mu.Lock()
		defer f.nodes[1].mu.Unlock()
		return f.nodes[1].active != nil && f.nodes[1].active.cfg.Revision == 2
	})
	if code := request(f.nodes[2], pull, ""); code != 403 {
		t.Fatal("withdrawn inventory route remained active", code)
	}
}

func TestDiscoveryRetriesPolicyLagWithoutExpandingAuthority(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, pull := f.rules()
	ctx := context.Background()
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	wait(t, func() bool { return complete(f.nodes[0], push.Job(f.domain.Trust, f.generation).Operation) })
	pull.PeerRevision = 2
	f.replicationConfig(t, 2, 1, pull)
	start(t, f.nodes[2])
	wait(t, func() bool {
		s, e := f.nodes[2].DiscoveryStatus(ctx)
		return e == nil && s.Routes[pull.ID(f.domain.Trust)].Phase == "RETRY_WAIT"
	})
	s, e := f.nodes[2].Status(ctx)
	must(t, e)
	if len(s.Jobs) != 0 {
		t.Fatal("future rule created unauthorized job", s)
	}
	f.replicationConfig(t, 1, 2, push, pull)
	wait(t, func() bool { return complete(f.nodes[2], pull.Job(f.domain.Trust, f.generation).Operation) })
}
