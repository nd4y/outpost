package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

func TestSignedWeightedAssignmentsKeepEligibleFallbackAndLegacyPublication(t *testing.T) {
	f := fixtureBytes(t, 128<<10)
	target := f.server(t, "s3", 0, nil)
	workers := append([]Worker(nil), f.workers...)
	workers[0].Weight, workers[1].Weight = 4, 2
	now := time.Now()
	d := Delegation{Format: DelegationFormat, Trust: f.authority.Generation, Epoch: 1,
		Profile: profile(target), AllowedClasses: []string{"trusted"}, Workers: workers,
		StartMillis: now.UnixMilli(), ExpiresUnix: now.Add(time.Minute).Unix(), SlotMillis: 1000}
	raw, err := SignDelegation(d, f.planner)
	must(t, err)
	ctx := context.Background()
	first, err := BuildDerived(ctx, f.replicas[0], f.id, raw, f.authority)
	must(t, err)
	second, err := BuildDerived(ctx, f.replicas[1], f.id, raw, f.authority)
	must(t, err)
	if !bytes.Equal(first, second) {
		t.Fatal("independent holders derived different weighted plans")
	}
	p, err := Verify(first, f.authority)
	must(t, err)
	legacy := p
	legacy.Workers = append([]Worker(nil), f.workers...)
	tasks, err := p.Tasks()
	must(t, err)
	for _, task := range tasks {
		seen := map[string]int{}
		for round := int64(0); round < 7; round++ {
			owner := p.owner(task.Part.ID, round)
			if owner != p.owner(task.Part.ID, round+7) {
				t.Fatal("weighted assignment did not repeat after its bounded cycle")
			}
			seen[owner]++
			if p.owner("publication", round) != legacy.owner("publication", round) {
				t.Fatal("weight changed historical publication rotation")
			}
		}
		for _, w := range workers {
			if seen[w.ID] != max(1, w.Weight) {
				t.Fatal("eligible worker lost a slot or received a different signed share", seen)
			}
		}
	}
	p.Workers[0].Weight = 3
	tampered, err := json.Marshal(p)
	must(t, err)
	if _, err = Verify(tampered, f.authority); !errors.Is(err, ErrDenied) {
		t.Fatal("worker altered its share outside the signed delegation", err)
	}
	for _, weight := range []int{-1, MaxWorkerWeight + 1} {
		d.Workers[0].Weight = weight
		if _, err = SignDelegation(d, f.planner); !errors.Is(err, ErrDenied) {
			t.Fatal("out-of-range weight signed", weight, err)
		}
	}
}

func TestDelegatedPlansAreIdenticalAcrossReplicasAndRecoverBothProtocols(t *testing.T) {
	for _, kind := range []string{"s3", "webdav"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			target := f.server(t, kind, 0, nil)
			ctx := context.Background()
			d := Delegation{Format: DelegationFormat, Trust: f.authority.Generation, Epoch: 1, Profile: profile(target), AllowedClasses: []string{"trusted"}, Workers: f.workers, StartMillis: time.Now().Add(200 * time.Millisecond).UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 60000}
			grant, e := SignDelegation(d, f.planner)
			must(t, e)
			var expected []byte
			children := []*child{}
			for i, r := range f.replicas {
				raw, e := BuildDerived(ctx, r, f.id, grant, f.authority)
				must(t, e)
				if i == 0 {
					expected = raw
				} else if !bytes.Equal(expected, raw) {
					t.Fatal("workers derived different assignment identities")
				}
				p, e := Verify(raw, f.authority)
				must(t, e)
				if p.Format != DerivedFormat || len(p.Signature) != 0 || p.Operation != DelegatedOperation(grant, f.id) {
					t.Fatal("wrong derived authority")
				}
				children = append(children, f.prepare(t, target, raw, i))
			}
			for _, c := range children {
				c.start(t)
			}
			for _, c := range children {
				c.wait(t, true)
			}
			for _, r := range f.replicas {
				must(t, r.Close())
			}
			for _, dir := range f.dirs {
				must(t, os.RemoveAll(dir))
			}
			must(t, f.store.Close())
			must(t, os.RemoveAll(filepath.Join(f.base, "source-store")))
			must(t, os.Remove(f.input))
			recoverBytes(t, f, target, f.id, f.version, f.data)
		})
	}
}

func TestDelegationRejectsScopeChangesAndUntrustedPartMapCannotPublish(t *testing.T) {
	f := newFixture(t)
	target := f.server(t, "webdav", 0, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	d := Delegation{Format: DelegationFormat, Trust: f.authority.Generation, Epoch: 1, Profile: profile(target), AllowedClasses: []string{"trusted"}, Workers: f.workers[:1], StartMillis: time.Now().Add(-time.Second).UnixMilli(), ExpiresUnix: time.Now().Add(time.Minute).Unix(), SlotMillis: 5000}
	grant, e := SignDelegation(d, f.planner)
	must(t, e)
	raw, e := BuildDerived(ctx, f.replicas[0], f.id, grant, f.authority)
	must(t, e)
	p, e := Verify(raw, f.authority)
	must(t, e)
	for _, mutate := range []func(*Plan){func(p *Plan) { p.Profile.Endpoint = "https://other.invalid" }, func(p *Plan) { p.Operation = storage.Hash([]byte("other")) }, func(p *Plan) { p.ExpiresUnix++ }, func(p *Plan) { p.Workers = nil }, func(p *Plan) { p.Format = Format }, func(p *Plan) { p.Signature = make([]byte, 64) }} {
		bad := p
		mutate(&bad)
		b, _ := json.Marshal(bad)
		if _, e = Verify(b, f.authority); e == nil {
			t.Fatal("delegation expanded")
		}
	}
	var bad Plan
	must(t, json.Unmarshal(raw, &bad))
	changed := false
	for n := range bad.Blobs {
		if len(bad.Blobs[n].Parts) > 1 {
			bad.Blobs[n].Parts[0].ID = storage.Hash([]byte("forged part mapping"))
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("fixture lacks multipart object")
	}
	untrusted, _ := json.Marshal(bad)
	// Scope verification is not proof of an untrusted split map's contents.
	_, e = Verify(untrusted, f.authority)
	must(t, e)
	dir := filepath.Join(f.base, "untrusted-plan")
	must(t, os.Mkdir(dir, 0700))
	j, e := Open(dir, untrusted, f.workers[0].ID, f.authority, true)
	must(t, e)
	defer j.Close()
	b := f.backend(t, target, 0)
	if _, e = j.Run(ctx, f.replicas[0], b, f.keys[0]); !errors.Is(e, storage.ErrIntegrity) {
		t.Fatal("incorrect part map did not fail byte verification", e)
	}
	if _, e = b.Catalog(ctx, f.id, f.authority.Generation); !storage.Missing(e) {
		t.Fatal("incorrect mapping published a complete target", e)
	}
}
