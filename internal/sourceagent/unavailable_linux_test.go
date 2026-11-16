package sourceagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
)

func TestSourceAllIngressUnavailablePreservesHeadAndBoundedCache(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	leaf, err := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, err)
	alternate := f.grant
	alternate.Ingress = peer.Identity(leaf)
	authority, err := ingress.SignAuthority(alternate, f.ownerSigner)
	must(t, err)
	var primaryUnavailable atomic.Bool
	var primaryReadiness, alternateReadiness, unexpected atomic.Int32
	f.intercept = func(out http.ResponseWriter, r *http.Request) bool {
		if !primaryUnavailable.Load() {
			return false
		}
		if strings.HasSuffix(r.URL.Path, "/readiness") {
			primaryReadiness.Add(1)
		} else {
			unexpected.Add(1)
		}
		http.Error(out, "primary unavailable", http.StatusServiceUnavailable)
		return true
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/readiness") {
			alternateReadiness.Add(1)
		} else {
			unexpected.Add(1)
		}
		http.Error(out, "alternate unavailable", http.StatusServiceUnavailable)
	}))
	server.TLS, err = peer.AuthenticatedServerTLS(f.replicaCertificate, f.roots, alternate.Ingress)
	must(t, err)
	server.StartTLS()
	t.Cleanup(server.Close)
	must(t, f.a.Close())
	f.a = nil
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "all-unavailable-agent")
	f.b.Standby = true
	f.b.Companion = &CompanionIngress{Endpoint: server.URL, AuthorityFile: filepath.Join(f.base, "unavailable-authority.json")}
	f.b.Profile.CopyTargets = []string{f.grant.Ingress, alternate.Ingress}
	must(t, os.WriteFile(f.b.Companion.AuthorityFile, authority, 0600))
	f.a, err = Open(ctx, f.b, true)
	must(t, err)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	checkpoint, err := f.a.Checkpoint(ctx)
	must(t, err)
	before, err := f.a.Status(ctx)
	must(t, err)
	if before.Phase != "COMPLETE" || before.Sequence != 1 || alternateReadiness.Load() != 0 {
		t.Fatal("first generation did not complete through primary", before)
	}
	old, err := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, err)
	changed := bytes.Repeat([]byte("changed source after all receivers refused"), 10000)
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), changed, 0640))
	cache := filepath.Join(f.b.Local.Directory, "cache")
	originalFiles, originalBytes := unavailableCacheSnapshot(t, cache)
	if len(originalFiles) == 0 || originalBytes > 2<<20 {
		t.Fatal("small fixture already exceeds its declared cache bound", originalBytes)
	}
	primaryUnavailable.Store(true)
	for attempt := 0; attempt < 3; attempt++ {
		if err = f.a.Next(ctx); !errors.Is(err, ingress.ErrUnavailable) {
			t.Fatal("all unavailable ingress did not refuse new capture", err)
		}
		f.reopen(t)
		status, err := f.a.Status(ctx)
		must(t, err)
		retained, err := f.a.Checkpoint(ctx)
		must(t, err)
		files, count := unavailableCacheSnapshot(t, cache)
		if status.Phase != "COMPLETE" || status.Operation != before.Operation || status.Sequence != before.Sequence || status.Generation != before.Generation || !bytes.Equal(retained, checkpoint) {
			t.Fatal("failed admission changed the last complete checkpoint", status)
		}
		if count != originalBytes || count > 2<<20 || !reflect.DeepEqual(files, originalFiles) {
			t.Fatal("unavailable receivers grew or changed the source cache", count, originalBytes)
		}
	}
	if primaryReadiness.Load() != 3 || alternateReadiness.Load() != 3 || unexpected.Load() != 0 {
		t.Fatal("readiness refusal admitted or wrote a capture", primaryReadiness.Load(), alternateReadiness.Load(), unexpected.Load())
	}
	owner := f.owner
	owner.SigningKey = nil
	restore := func(label, id string, expected []byte) {
		t.Helper()
		out := filepath.Join(f.base, label)
		_, err := generation.RecoverMaterialized(ctx, f.replicaPath, id, f.grant.Trust, owner, generation.RecoverySelection{}, out)
		must(t, err)
		actual, err := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, err)
		if !bytes.Equal(actual, expected) {
			t.Fatal("independent retained version differs", label)
		}
	}
	// This restoration succeeds while both authenticated endpoints still refuse.
	restore("old-while-all-unavailable", before.Generation, old)
	if unexpected.Load() != 0 {
		t.Fatal("local restore contacted an unavailable ingress")
	}
	primaryUnavailable.Store(false)
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	after, err := f.a.Status(ctx)
	must(t, err)
	if after.Phase != "COMPLETE" || after.Sequence != 2 || after.Generation == before.Generation || after.Operation == before.Operation {
		t.Fatal("returning ingress did not publish exactly the next generation", after)
	}
	must(t, f.a.Close())
	f.a = nil
	must(t, os.RemoveAll(f.tree))
	restore("old-after-return-and-source-loss", before.Generation, old)
	restore("new-after-return-and-source-loss", after.Generation, changed)
	if alternateReadiness.Load() != 3 || unexpected.Load() != 0 {
		t.Fatal("successful retry changed receiver or used unavailable endpoint")
	}
	t.Logf("UNAVAILABLE_INGRESS receivers=2 attempts=3 cacheBytes=%d cacheStable=true payloadAdmissions=0 retainedRestores=2 newRestores=1", originalBytes)
}

// Only regular cache files enter this logical byte/hash inventory. Directory
// timestamps and flock state are not payload growth or persistence evidence.
func unavailableCacheSnapshot(t *testing.T, root string) (map[string][32]byte, int64) {
	t.Helper()
	files := make(map[string][32]byte)
	var total int64
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("unexpected nonregular source cache entry")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative] = sha256.Sum256(data)
		total += info.Size()
		return nil
	})
	must(t, err)
	return files, total
}
