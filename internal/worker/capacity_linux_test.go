package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestCapacityBlockedNewGenerationPreservesCompleteHistory(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	push, _ := f.jobs()
	sourceConfig := f.config(t, 0, []control.Job{push})
	targetConfig := f.cfg
	targetConfig.Node = f.nodes[1].node
	targetConfig.Domains = []control.Domain{f.domain}
	targetConfig.Jobs = []control.Job{push}
	targetConfig.Limits.CapacityBytes = 16 << 20
	targetConfig.Limits.ReserveBytes = (10 << 20) + (256 << 10)
	targetConfig.Limits.SpoolBytes = 4 << 20
	targetConfig.Limits.TelemetryBytes = 1 << 20
	raw, e := control.Sign(targetConfig, f.owner)
	must(t, e)
	must(t, f.nodes[1].Accept(context.Background(), raw))
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	wait(t, func() bool { return complete(f.nodes[0], push.Operation) })
	stopA()
	source, e := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, false)
	must(t, e)
	defer source.Close()
	_, prior, e := source.LoadVersion(f.version)
	must(t, e)
	updated := make([]byte, 1<<20)
	_, e = rand.Read(updated)
	must(t, e)
	input := filepath.Join(f.base, "input")
	must(t, os.WriteFile(input, updated, 0640))
	stats, e := source.Backup(context.Background(), input, filekit.BackupOptions{File: prior.File, Previous: f.version, Names: prior.Names})
	must(t, e)
	replica, e := generation.Open(filepath.Join(DomainDirectory(f.nodes[0].dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer replica.Close()
	next, e := generation.Seal(context.Background(), source, []string{stats.Version}, replica, generation.Catalog{Format: generation.Format, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 2, Parent: f.generation, SnapshotUnix: time.Now().Unix(), Policy: 2, KitFormat: generation.KitFormat}, f.writer)
	must(t, e)
	push.Operation = storage.Hash([]byte("larger-generation"))
	push.PeerRevision = 2
	push.Generation = next
	sourceConfig.Revision = 2
	sourceConfig.Jobs = []control.Job{push}
	targetConfig.Revision = 2
	targetConfig.Jobs = []control.Job{push}
	for i, c := range []control.Config{sourceConfig, targetConfig} {
		raw, e = control.Sign(c, f.owner)
		must(t, e)
		must(t, f.nodes[i].Accept(context.Background(), raw))
	}
	stopA = start(t, f.nodes[0])
	wait(t, func() bool {
		s, e := f.nodes[0].Status(context.Background())
		return e == nil && s.Jobs[push.Operation].Phase == "BLOCKED" && s.Jobs[push.Operation].ErrorCode == "CAPACITY_BLOCKED"
	})
	stopA()
	stopB()
	target, e := generation.Open(filepath.Join(DomainDirectory(f.nodes[1].dir, f.domain.Trust), "replica"), f.domain.Trust, false)
	must(t, e)
	defer target.Close()
	state, e := target.Status(context.Background())
	must(t, e)
	if state.LatestComplete != f.generation {
		t.Fatal("partial new generation displaced complete history")
	}
	must(t, target.VerifyComplete(context.Background(), f.generation))
	kit := filepath.Join(f.base, "protected-kit")
	must(t, target.ExportKit(context.Background(), f.generation, f.version, kit))
	owner := f.dataOwner
	owner.SigningKey = nil
	reader, e := filekit.OpenStore(kit, owner, false)
	must(t, e)
	defer reader.Close()
	out := filepath.Join(f.base, "protected-restore")
	_, e = reader.Restore(context.Background(), f.version, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, prior.Names[0]))
	must(t, e)
	if !bytes.Equal(got, f.content) {
		t.Fatal("protected version no longer restores")
	}
}
