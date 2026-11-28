package worker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestWorkerMaintenanceRequiresBoundSurvivorCopies(t *testing.T) {
	f := newFixture(t)
	f.cfg.Limits.AttemptMillis = 60000
	f.domain.RetirementMinimumCopies = 1
	f.endpoint(t, nil)
	r, head, makeCommand := maintenanceCommandFixture(t, f)
	retiring, survivor := f.nodes[0], f.nodes[1]
	ctx := context.Background()
	trust := f.domain.Trust
	cfg := f.cfg
	cfg.Node = survivor.node
	cfg.Domains = []control.Domain{f.domain}
	cfg.Jobs = nil
	raw, e := control.Sign(cfg, f.owner)
	must(t, e)
	must(t, survivor.Accept(ctx, raw))
	dir := filepath.Join(DomainDirectory(survivor.dir, trust), "replica")
	must(t, os.MkdirAll(dir, 0700))
	copy, e := generation.Open(dir, trust, true)
	must(t, e)
	defer copy.Close()
	catalog, e := r.Catalog(ctx, f.generation)
	must(t, e)
	id, e := copy.Receive(ctx, catalog, func(ref generation.Object) ([]byte, error) {
		return r.ReadObject(ctx, f.generation, ref)
	})
	must(t, e)
	if id != f.generation {
		t.Fatal("survivor has a different generation")
	}

	legacyOp := storage.Hash([]byte("legacy retirement"))
	legacy := maintenancePermit(t, f, r, legacyOp, f.maintenance, id)
	env := makeCommand(legacy, legacyOp, 1)
	ack, e := retiring.ExecuteCommand(ctx, env)
	must(t, e)
	if a := verifyWorkerAck(t, retiring, env, ack); a.State != "FAILED" || a.ErrorCode != "POLICY_BLOCKED" {
		t.Fatal("legacy permit bypassed the domain minimum", a)
	}

	op := storage.Hash([]byte("covered retirement"))
	now := time.Now().Unix()
	grant, e := generation.SignRetentionProtection(generation.RetentionProtection{
		Format: generation.RetentionProtectionFormat, Node: survivor.node, Domain: trust.Domain,
		Repository: trust.Repository, Epoch: trust.Epoch, Operation: storage.Hash([]byte("survivor hold")),
		Generation: id, Action: "HOLD", NotBefore: now - 60, ExpiresUnix: now + 120,
		Retirement: &generation.RetirementBinding{Node: retiring.node, Operation: op},
	}, f.maintenance)
	must(t, e)
	witness, e := survivor.ApplyRetentionProtection(ctx, trust.Domain, grant)
	must(t, e)
	status, e := r.Status(ctx)
	must(t, e)
	p := generation.Permit{
		Format: generation.RetentionPermitFormat, Domain: trust.Domain, Repository: trust.Repository,
		Epoch: trust.Epoch, Revision: status.Revision, Operation: op, Retire: []string{id},
		Window:   &generation.PermitWindow{Node: retiring.node, StartUnix: now - 1, ExpiresUnix: now + 120},
		Coverage: &generation.RetentionCoverage{MinimumCopies: 1, Witnesses: []generation.RetentionProtectionReceipt{witness}},
	}
	duplicate := p
	duplicate.Coverage = &generation.RetentionCoverage{MinimumCopies: 2, Witnesses: []generation.RetentionProtectionReceipt{witness, witness}}
	if _, e = generation.SignPermit(duplicate, f.maintenance); !errors.Is(e, generation.ErrInvalid) {
		t.Fatal("duplicate node counted twice", e)
	}
	uncovered := p
	uncovered.Retire = []string{head}
	if _, e = generation.SignPermit(uncovered, f.maintenance); !errors.Is(e, generation.ErrInvalid) {
		t.Fatal("different generation counted as covered", e)
	}
	wrongOp := p
	wrongOp.Operation = legacyOp
	if _, e = generation.SignPermit(wrongOp, f.maintenance); !errors.Is(e, generation.ErrInvalid) {
		t.Fatal("different retirement operation counted as covered", e)
	}

	tampered := p
	tamperedWitness := witness
	tamperedWitness.ObservedUnix++
	tampered.Coverage = &generation.RetentionCoverage{MinimumCopies: 1, Witnesses: []generation.RetentionProtectionReceipt{tamperedWitness}}
	if _, e = generation.SignPermit(tampered, f.maintenance); !errors.Is(e, generation.ErrInvalid) {
		t.Fatal("altered witness signature admitted", e)
	}

	covered, e := generation.SignPermit(p, f.maintenance)
	must(t, e)
	req := command.Request{Kind: "maintenance", Domain: trust.Domain, Operation: op, MaintenancePermit: covered, ExpiresUnix: now + 120}
	cfg.Node = retiring.node
	_, e = cfg.MaintenancePermit(req)
	must(t, e)
	stricter := cfg
	stricter.Domains = slices.Clone(cfg.Domains)
	stricter.Domains[0].RetirementMinimumCopies = 2
	if _, e = stricter.MaintenancePermit(req); !errors.Is(e, control.ErrDenied) {
		t.Fatal("permit lowered signed domain minimum", e)
	}
	changed := cfg
	changed.Nodes = slices.Clone(cfg.Nodes)
	for i := range changed.Nodes {
		if changed.Nodes[i].ID == survivor.node {
			changed.Nodes[i].Class = "untrusted"
		}
	}
	if _, e = changed.MaintenancePermit(req); !errors.Is(e, control.ErrDenied) {
		t.Fatal("untrusted witness admitted", e)
	}
	changed = cfg
	changed.Domains = slices.Clone(cfg.Domains)
	changed.Domains[0].Placement.Holders = []string{retiring.node}
	if _, e = changed.MaintenancePermit(req); !errors.Is(e, control.ErrDenied) {
		t.Fatal("non-holder witness admitted", e)
	}
	gcOp := storage.Hash([]byte("orphan-only collection"))
	gc := maintenancePermit(t, f, r, gcOp, f.maintenance)
	_, e = cfg.MaintenancePermit(command.Request{Kind: "maintenance", Domain: trust.Domain, Operation: gcOp, MaintenancePermit: gc, ExpiresUnix: now + 120})
	must(t, e)

	env = makeCommand(covered, op, 2)
	ack, e = retiring.ExecuteCommand(ctx, env)
	must(t, e)
	if len(ack) != 0 {
		t.Fatal("admission claimed execution")
	}
	stop := start(t, retiring)
	var record CommandRecord
	waitFor(t, 60*time.Second, func() bool {
		record = actionRecord(t, retiring, env)
		return len(record.Ack) != 0
	})
	stop()
	if a := verifyWorkerAck(t, retiring, env, record.Ack); a.State != "COMPLETE" {
		t.Fatal("covered retirement did not complete", a)
	}
	if e = r.VerifyComplete(ctx, id); !errors.Is(e, generation.ErrIncomplete) {
		t.Fatal("retiring replica still declares the old copy", e)
	}
	must(t, r.VerifyComplete(ctx, head))
	must(t, copy.VerifyComplete(ctx, id))
}
