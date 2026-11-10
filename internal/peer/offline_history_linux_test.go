package peer

import (
	"encoding/binary"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

func TestOfflineHistoryAcrossMaintenanceAndPolicyChange(t *testing.T) {
	updates := uint64(3)
	if os.Getenv("OUTPOST_OFFLINE_180") == "1" {
		if os.Getenv("OUTPOST_TEST_ROOT") == "" {
			t.Fatal("the 180-generation run requires the admitted HDD test root")
		}
		updates = 180
	}
	const day = 24 * time.Hour
	const authorityLifetime = 187 * day
	f := newFixtureWithAuthority(t, newAuthorityWithLifetime(t, authorityLifetime, authorityLifetime))
	grantUntil := time.Now().Add(authorityLifetime).Unix()
	policy := func(self *node, peers ...*node) Policy {
		p := f.policy(self, peers...)
		for id, grant := range p.Peers {
			grant.ExpiresUnix = grantUntil
			p.Peers[id] = grant
		}
		return p
	}
	base := time.Now().Add(-time.Duration(updates) * day)
	seal := func(seq uint64, parent string, revision uint64) (string, string, []byte) {
		body := append([]byte(nil), f.old[:64<<10]...)
		binary.BigEndian.PutUint64(body, seq)
		must(t, os.WriteFile(f.input, body, 0640))
		id, version := f.sealAt(t, seq, parent, base.Add(time.Duration(seq-1)*day).Unix(), revision)
		return id, version, body
	}
	first, firstVersion, firstBody := seal(1, "", 1)
	bridge := f.endpoint(t, f.a, policy(f.a, f.b, f.c), nil)
	push := f.client(t, f.b, f.a, bridge.URL, policy(f.b, f.a))
	_, e := push.Push(testContext, generation.Hash([]byte("offline initial push")), first, f.b.replica)
	must(t, e)
	pull := f.client(t, f.c, f.a, bridge.URL, policy(f.c, f.a))
	_, e = pull.Pull(testContext, generation.Hash([]byte("offline initial pull")), first, f.c.replica)
	must(t, e)
	pull.Close()
	must(t, f.c.replica.Close())
	must(t, f.c.journal.Close())
	push.Close()
	bridge.Close()

	// Change the admitted peer set while C is offline. Only B can reach the
	// bridge during the intervening generations and independent maintenance.
	bridge = f.endpoint(t, f.a, policy(f.a, f.b), nil)
	push = f.client(t, f.b, f.a, bridge.URL, policy(f.b, f.a))
	current, version, body := first, firstVersion, firstBody
	for seq := uint64(2); seq <= updates+1; seq++ {
		previous := current
		current, version, body = seal(seq, previous, 2)
		op := generation.Hash([]byte("offline push/" + strconv.FormatUint(seq, 10)))
		_, e = push.Push(testContext, op, current, f.b.replica)
		must(t, e)
		for _, n := range []*node{f.a, f.b} {
			s, e := n.replica.Status(testContext)
			must(t, e)
			permit, e := generation.SignPermit(generation.Permit{Format: generation.Format, Domain: f.trust.Domain, Repository: f.trust.Repository, Epoch: f.trust.Epoch, Revision: s.Revision, Operation: generation.Hash([]byte("offline retire/" + n.id + "/" + previous)), Retire: []string{previous}}, f.maintenance)
			must(t, e)
			_, e = n.replica.Maintain(testContext, permit)
			must(t, e)
		}
	}
	for _, n := range []*node{f.a, f.b} {
		s, e := n.replica.Status(testContext)
		must(t, e)
		if s.HighestSequence != updates+1 || len(s.Complete) != 1 || s.LatestComplete != current {
			t.Fatal("retention did not leave only the final complete generation", s)
		}
	}
	push.Close()
	bridge.Close()
	must(t, f.source.Close())
	must(t, f.b.replica.Close())
	must(t, f.b.journal.Close())

	f.c.replica, e = generation.Open(filepath.Join(f.c.dir, "replica"), f.trust, false)
	must(t, e)
	f.c.journal, e = OpenJournal(filepath.Join(f.c.dir, "journal"), f.c.id, f.trust, false)
	must(t, e)
	var blockObjects atomic.Bool
	blockObjects.Store(true)
	bridge = f.endpoint(t, f.a, policy(f.a, f.c), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if blockObjects.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/objects/") {
				http.Error(w, "fixture link interrupted", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	pull = f.client(t, f.c, f.a, bridge.URL, policy(f.c, f.a))
	op := generation.Hash([]byte("offline final pull"))
	if _, e = pull.Pull(testContext, op, current, f.c.replica); e == nil {
		t.Fatal("interrupted catch-up reported a complete copy")
	}
	s, e := f.c.replica.Status(testContext)
	must(t, e)
	if s.LatestComplete != first || len(s.Receiving) != 1 || s.Receiving[0] != current {
		t.Fatal("interrupted catch-up replaced the old complete generation", s)
	}
	blockObjects.Store(false)
	_, e = pull.Pull(testContext, op, current, f.c.replica)
	must(t, e)
	bridge.Close()
	s, e = f.c.replica.Status(testContext)
	must(t, e)
	if s.HighestSequence != updates+1 || len(s.Complete) != 2 || s.LatestComplete != current || len(s.Receiving) != 0 {
		t.Fatal("catch-up replayed obsolete history or missed the final generation", s)
	}
	restore(t, f, f.c, first, firstVersion, firstBody)
	restore(t, f, f.c, current, version, body)
	t.Logf("simulated daily updates=%d, remote complete before/after=1/2, authority days=187", updates)
}
