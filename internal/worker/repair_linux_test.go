package worker

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func damageWorkerReplica(t *testing.T, f *fixture, index int) generation.RepairNeed {
	t.Helper()
	dir := filepath.Join(DomainDirectory(f.nodes[index].dir, f.domain.Trust), "replica")
	r, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	defer r.Close()
	raw, e := r.Catalog(context.Background(), f.generation)
	must(t, e)
	refs, e := generation.Dependencies(raw, f.domain.Trust)
	must(t, e)
	victim := refs[0]
	name := filepath.Join(dir, "objects", victim.ID)
	bad, e := os.ReadFile(name)
	must(t, e)
	bad[0] ^= 1
	must(t, os.WriteFile(name, bad, 0600))
	if e = r.Complete(context.Background(), f.generation); !errors.Is(e, generation.ErrIncomplete) {
		t.Fatal("corruption not detected", e)
	}
	needs, e := r.RepairNeeds(context.Background())
	must(t, e)
	if len(needs) != 1 {
		t.Fatal("repair need not persisted", needs)
	}
	return needs[0]
}

func TestIntegrityRepairAutonomousPushPullAcrossRestartAndOutboundOnlyRoutes(t *testing.T) {
	exerciseAutonomousRepair(t, damageWorkerReplica, false)
}
func TestCatalogRepairAutonomousPushPullAcrossRestartAndOutboundOnlyRoutes(t *testing.T) {
	exerciseAutonomousRepair(t, damageWorkerCatalog, true)
}
func damageWorkerCatalog(t *testing.T, f *fixture, index int) generation.RepairNeed {
	t.Helper()
	dir := filepath.Join(DomainDirectory(f.nodes[index].dir, f.domain.Trust), "replica")
	r, e := generation.Open(dir, f.domain.Trust, false)
	must(t, e)
	defer r.Close()
	path := filepath.Join(dir, "catalogs", f.generation)
	raw, e := os.ReadFile(path)
	must(t, e)
	raw[0] ^= 1
	must(t, os.WriteFile(path, raw, 0600))
	if _, e = r.Catalog(context.Background(), f.generation); !errors.Is(e, generation.ErrCatalogUnavailable) {
		t.Fatal("catalog damage not detected", e)
	}
	needs, e := r.RepairNeeds(context.Background())
	must(t, e)
	if len(needs) != 1 {
		t.Fatal(needs)
	}
	return needs[0]
}
func exerciseAutonomousRepair(t *testing.T, damage func(*testing.T, *fixture, int) generation.RepairNeed, catalog bool) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, pull := f.rules()
	push.Repair = true
	pull.Repair = true
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	f.replicationConfig(t, 2, 1, pull)
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	stopC := start(t, f.nodes[2])
	originalA, originalC := push.Job(f.domain.Trust, f.generation), pull.Job(f.domain.Trust, f.generation)
	wait(t, func() bool {
		return complete(f.nodes[0], originalA.Operation) && complete(f.nodes[2], originalC.Operation)
	})
	beforeA, e := f.nodes[0].Status(context.Background())
	must(t, e)
	beforeC, e := f.nodes[2].Status(context.Background())
	must(t, e)
	stopA()
	stopC()
	stopB()
	bNeed := damage(t, f, 1)
	cNeed := damage(t, f, 2)
	// The relay alone listens. Both endpoints still initiate their own HTTPS
	// connections; no control publication or reverse network route is added.
	stopB = start(t, f.nodes[1])
	defer stopB()
	stopA = start(t, f.nodes[0])
	defer stopA()
	stopC = start(t, f.nodes[2])
	defer stopC()
	repairedA := push.RepairJob(f.domain.Trust, bNeed.Generation, bNeed.Token)
	repairedC := pull.RepairJob(f.domain.Trust, cNeed.Generation, cNeed.Token)
	wait(t, func() bool {
		return complete(f.nodes[0], repairedA.Operation) && complete(f.nodes[2], repairedC.Operation)
	})
	afterA, e := f.nodes[0].Status(context.Background())
	must(t, e)
	afterC, e := f.nodes[2].Status(context.Background())
	must(t, e)
	for _, pair := range [][2]JobState{{beforeA.Jobs[originalA.Operation], afterA.Jobs[originalA.Operation]}, {beforeC.Jobs[originalC.Operation], afterC.Jobs[originalC.Operation]}} {
		a, _ := json.Marshal(pair[0])
		b, _ := json.Marshal(pair[1])
		if !bytes.Equal(a, b) {
			t.Fatal("automatic repair rewrote original operation")
		}
	}
	stopA()
	stopC()
	stopB()
	for _, index := range []int{1, 2} {
		dir := filepath.Join(DomainDirectory(f.nodes[index].dir, f.domain.Trust), "replica")
		r, e := generation.Open(dir, f.domain.Trust, false)
		must(t, e)
		must(t, r.VerifyComplete(context.Background(), f.generation))
		journal, e := r.Integrity(context.Background())
		must(t, e)
		must(t, r.Close())
		repairs, damages := journal.Repairs, journal.Damage
		if catalog {
			repairs, damages = journal.CatalogRepairs, journal.CatalogDamage
		}
		if len(repairs) != 1 || len(damages) != 0 {
			t.Fatal("automatic repair has no durable quarantine", journal)
		}
		out := filepath.Join(f.base, "repaired-recovery-"+f.cfg.Nodes[index].ID)
		_, e = generation.RecoverMaterialized(context.Background(), dir, f.generation, f.domain.Trust, f.dataOwner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
		must(t, e)
		if !bytes.Equal(got, f.content) {
			t.Fatal("automatic repair restore differs")
		}
	}
}

func TestIntegrityRepairNeedsRequiresExactCurrentPushDelegation(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	push, pull := f.rules()
	push.Repair = true
	pull.Repair = true
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	stop := start(t, f.nodes[1])
	defer stop()
	wait(t, func() bool { f.nodes[1].mu.Lock(); defer f.nodes[1].mu.Unlock(); return f.nodes[1].active != nil })
	request := func(index int, rule control.Replication, suffix string) int {
		client := &http.Client{Timeout: time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[index].cert}}}}
		defer client.CloseIdleConnections()
		req, e := http.NewRequest(http.MethodGet, server.URL+"/v1/"+f.domain.Trust.Domain+"/repair-needs"+suffix, nil)
		must(t, e)
		req.Header.Set("Outpost-Replication", rule.ID(f.domain.Trust))
		req.Header.Set("Outpost-Required-Revision", "1")
		res, e := client.Do(req)
		must(t, e)
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, res.Body)
		return res.StatusCode
	}
	if code := request(0, push, ""); code != 200 {
		t.Fatal("authorized sender cannot discover repair", code)
	}
	for _, code := range []int{request(2, push, ""), request(2, pull, ""), request(0, push, "?extra=1")} {
		if code != 403 {
			t.Fatal("reverse/foreign/query repair metadata allowed", code)
		}
	}
	noRepair := push
	noRepair.Repair = false
	f.replicationConfig(t, 1, 2, noRepair, pull)
	wait(t, func() bool {
		f.nodes[1].mu.Lock()
		defer f.nodes[1].mu.Unlock()
		return f.nodes[1].active != nil && f.nodes[1].active.cfg.Revision == 2
	})
	if code := request(0, push, ""); code != 403 {
		t.Fatal("withdrawn repair metadata allowed", code)
	}
	if code := request(0, noRepair, ""); code != 403 {
		t.Fatal("ordinary replication granted repair metadata", code)
	}
}
