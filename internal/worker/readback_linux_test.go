package worker

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

func TestOwnerReadbackPolicyEnablesReuseAndRestoresFreshOnlyAudits(t *testing.T) {
	f := newFixture(t)
	f.endpoint(t, nil)
	f.domain.PeerReadbackMaxAgeSeconds = 3600
	job, _ := f.jobs()
	f.config(t, 1, []control.Job{job})
	f.config(t, 0, []control.Job{job})
	stopB, stopA := start(t, f.nodes[1]), start(t, f.nodes[0])
	defer stopB()
	defer stopA()
	inspect := func(j control.Job) peer.Result {
		wait(t, func() bool { return complete(f.nodes[0], j.Operation) })
		status, e := f.nodes[0].Status(context.Background())
		must(t, e)
		var r peer.Result
		must(t, json.Unmarshal(status.Jobs[j.Operation].Receipt, &r))
		return r
	}
	first := inspect(job)
	if first.CachedObjects != 0 || first.Receipt.Verification != "client-full-readback" {
		t.Fatal("first read was not fresh", first)
	}
	f.cfg.Revision = 2
	job.PeerRevision = 2
	job.Operation = storage.Hash([]byte("explicit repeat audit"))
	f.config(t, 1, []control.Job{job})
	f.config(t, 0, []control.Job{job})
	repeated := inspect(job)
	if repeated.CachedObjects == 0 || repeated.Receipt.Verification != "client-cached-readback" || repeated.Receipt.ObservedUnix > first.Receipt.ObservedUnix {
		t.Fatal("owner reuse policy was not applied", repeated)
	}
	f.cfg.Revision = 3
	f.domain.PeerReadbackMaxAgeSeconds = 0
	job.PeerRevision = 3
	job.Operation = storage.Hash([]byte("fresh-only audit"))
	f.config(t, 1, []control.Job{job})
	f.config(t, 0, []control.Job{job})
	fresh := inspect(job)
	if fresh.CachedObjects != 0 || fresh.Receipt.Verification != "client-full-readback" {
		t.Fatal("withdrawn reuse remained active", fresh)
	}
}
