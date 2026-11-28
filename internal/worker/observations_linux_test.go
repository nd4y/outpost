package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestOutboundOnlyNodePublishesOriginalObservationThroughCollector(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	ctx := context.Background()
	push, pull := f.rules()
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.domain.Trust, Reader: f.nodes[0].node, Collector: f.nodes[1].node, Targets: []string{f.nodes[2].node}, Epoch: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, MaxAgeSeconds: 3600}
	grant, e := observation.SignGrant(g, f.owner)
	must(t, e)
	configure := func(index int, revision uint64, grants []json.RawMessage, rules ...control.Replication) {
		c := f.cfg
		c.Node = f.nodes[index].node
		c.Revision = revision
		c.Domains = []control.Domain{f.domain}
		c.Replication = rules
		c.Observations = grants
		c.Jobs = nil
		raw, e := control.Sign(c, f.owner)
		must(t, e)
		must(t, f.nodes[index].Accept(ctx, raw))
	}
	configure(0, 1, nil, push)
	configure(1, 1, []json.RawMessage{grant}, push, pull)
	configure(2, 1, []json.RawMessage{grant}, pull)
	stopB := start(t, f.nodes[1])
	start(t, f.nodes[0])
	stopC := start(t, f.nodes[2])
	reader, e := observation.NewClient(server.URL, grant, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, time.Second)
	must(t, e)
	defer reader.Close()
	var original []byte
	wait(t, func() bool {
		proofs, e := reader.Read(ctx, f.generation)
		if e != nil || len(proofs) != 1 {
			return false
		}
		original = bytes.Clone(proofs[0])
		return true
	})
	p, e := observation.VerifyProof(original, grant, f.owner.Public().(ed25519.PublicKey), f.generation, time.Now())
	must(t, e)
	if p.Target != f.nodes[2].node {
		t.Fatal("collector impersonated replica")
	}
	// Both replicas can stop; the collector reopens exact stored signed bytes.
	stopC()
	stopB()
	stopB = start(t, f.nodes[1])
	defer stopB()
	wait(t, func() bool {
		proofs, e := reader.Read(ctx, f.generation)
		return e == nil && len(proofs) == 1 && bytes.Equal(proofs[0], original)
	})
	bad := p
	bad.ObservedUnix++
	tampered, _ := json.Marshal(bad)
	if _, e = f.nodes[1].saveObservation(ctx, grant, tampered); !errors.Is(e, observation.ErrDenied) {
		t.Fatal("relay refreshed signature", e)
	}
	unknown := storage.Hash([]byte("unknown"))
	if _, e = reader.Read(ctx, unknown); !errors.Is(e, observation.ErrPending) {
		t.Fatal("unknown generation produced evidence", e)
	}
	configure(1, 2, nil, push, pull)
	wait(t, func() bool { _, e := reader.Read(ctx, f.generation); return errors.Is(e, observation.ErrDenied) })
	if _, e = f.nodes[1].readObservation(ctx, grant, f.generation, f.nodes[2].node); e != nil {
		t.Fatal("withdrawal deleted retained evidence", e)
	}
}

func TestObservationOverloadIsBoundedAndRevocationJoinsBlockedBodies(t *testing.T) {
	f := newFixture(t)
	server := f.endpoint(t, nil)
	ctx := context.Background()
	push, _ := f.rules()
	g := observation.Grant{Format: observation.GrantFormat, Trust: f.domain.Trust, Reader: f.nodes[0].node, Collector: f.nodes[1].node, Targets: []string{f.nodes[2].node}, Epoch: 1, NotBefore: f.cfg.NotBefore, ExpiresUnix: f.cfg.ExpiresUnix, MaxAgeSeconds: 3600}
	grant, e := observation.SignGrant(g, f.owner)
	must(t, e)
	c := f.cfg
	c.Node = f.nodes[1].node
	c.Domains = []control.Domain{f.domain}
	c.Replication = []control.Replication{push}
	c.Observations = []json.RawMessage{grant}
	raw, e := control.Sign(c, f.owner)
	must(t, e)
	must(t, f.nodes[1].Accept(ctx, raw))
	f.replicationConfig(t, 0, 1, push)
	start(t, f.nodes[1])
	start(t, f.nodes[0])
	wait(t, func() bool { return complete(f.nodes[0], push.Job(f.domain.Trust, f.generation).Operation) })
	reader, e := observation.NewClient(server.URL, grant, f.owner.Public().(ed25519.PublicKey), f.nodes[0].cert, f.ca.pool, time.Second)
	must(t, e)
	defer reader.Close()
	proofs, e := reader.Read(ctx, f.generation)
	must(t, e)
	if len(proofs) != 0 {
		t.Fatal("unexpected proof before replica observation")
	}
	for n := 0; n < c.Limits.Parallel; n++ {
		conn, e := tls.Dial("tcp", strings.TrimPrefix(server.URL, "https://"), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{f.nodes[2].cert}})
		must(t, e)
		defer conn.Close()
		must(t, conn.SetDeadline(time.Now().Add(8*time.Second)))
		_, e = fmt.Fprintf(conn, "PUT /v1/%s/observations/%s/%s/%s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 1024\r\n\r\n{", g.Trust.Domain, storage.Hash(grant), f.generation, f.nodes[2].node)
		must(t, e)
	}
	wait(t, func() bool {
		f.nodes[1].mu.Lock()
		defer f.nodes[1].mu.Unlock()
		v := f.nodes[1].active
		return v != nil && len(v.metadata) == c.Limits.Parallel
	})
	if _, e = reader.Read(ctx, f.generation); !errors.Is(e, observation.ErrPending) {
		t.Fatal("metadata overload did not refuse new request", e)
	}
	c.Revision++
	c.Observations = nil
	raw, e = control.Sign(c, f.owner)
	must(t, e)
	must(t, f.nodes[1].Accept(ctx, raw))
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f.nodes[1].mu.Lock()
		v := f.nodes[1].active
		ready := v != nil && v.cfg.Revision == 2
		f.nodes[1].mu.Unlock()
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("withdrawn observation requests prevented policy replacement")
}
