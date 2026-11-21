package ingress

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

type crashFixture struct {
	Authority, Intent, Owner, Raw []byte
	Trust                         generation.Trust
	Objects                       map[string][]byte
}

func TestIngressCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_INGRESS_CHILD") != "1" {
		return
	}
	base := os.Getenv("OUTPOST_INGRESS_ROOT")
	raw, e := os.ReadFile(filepath.Join(base, "child.json"))
	must(t, e)
	var input crashFixture
	must(t, json.Unmarshal(raw, &input))
	r, e := generation.Open(filepath.Join(base, "replica"), input.Trust, false)
	must(t, e)
	defer r.Close()
	s, e := OpenSession(context.Background(), SessionOptions{Directory: filepath.Join(base, "session"), Authority: input.Authority, Intent: input.Intent, Owner: ed25519.PublicKey(input.Owner), Replica: r})
	must(t, e)
	defer s.Close()
	point := os.Getenv("OUTPOST_INGRESS_POINT")
	fault := func(name string) error {
		if name == point {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	s.Fault = fault
	r.Fault = fault
	for id, b := range input.Objects {
		_, e = s.Write(context.Background(), filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	for n := 0; n < 10; n++ {
		batch, receipt, e := s.FinishBatch(context.Background(), input.Raw, 1, generation.MaxObject)
		must(t, e)
		if batch.Complete {
			if strings.HasPrefix(point, "capture-ack-") || point == "capture-staged-object-removed" {
				_, e = s.Acknowledge(context.Background(), receipt, 256)
				must(t, e)
			}
			break
		}
	}
	t.Fatal("expected SIGKILL boundary absent")
}
func TestIngressSIGKILLDurabilityAndPublicationBoundaries(t *testing.T) {
	for _, point := range []string{"capture-object-durable", "capture-catalog-durable", "verification-batch-durable", "capture-replica-complete", "capture-receipt-durable", "capture-ack-durable", "capture-ack-unpinned", "capture-staged-object-removed"} {
		t.Run(point, func(t *testing.T) {
			f := setup(t)
			ctx := context.Background()
			payload := []byte("opaque payload")
			root := []byte("opaque kit root")
			i := f.intent
			catalog := generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, Policy: i.Policy, SnapshotUnix: i.SnapshotUnix, KitFormat: generation.KitFormat, Kits: []generation.Kit{{File: storage.Hash([]byte("file")), Version: storage.Hash([]byte("version")), Root: generation.Object{ID: storage.Hash(root), Bytes: len(root)}, Objects: []generation.Object{{ID: storage.Hash(payload), Bytes: len(payload)}}}}}
			raw, e := generation.SignCatalog(catalog, f.writer)
			must(t, e)
			objects := map[string][]byte{storage.Hash(root): root, storage.Hash(payload): payload}
			input := crashFixture{Authority: f.options.Authority, Intent: f.options.Intent, Owner: f.options.Owner, Trust: f.authority.Trust, Raw: raw, Objects: objects}
			b, e := json.Marshal(input)
			must(t, e)
			must(t, os.WriteFile(filepath.Join(f.base, "child.json"), b, 0600))
			must(t, f.source.Close())
			f.source = nil
			must(t, f.session.Close())
			f.session = nil
			must(t, f.options.Replica.Close())
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			command := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestIngressCrashChild$", "-test.v")
			command.Env = append(os.Environ(), "OUTPOST_INGRESS_CHILD=1", "OUTPOST_INGRESS_ROOT="+f.base, "OUTPOST_INGRESS_POINT="+point)
			output, e := command.CombinedOutput()
			if e == nil || bounded.Err() != nil {
				t.Fatalf("child did not reach bounded kill: %v %s", e, output)
			}
			exit, ok := e.(*exec.ExitError)
			if !ok {
				t.Fatalf("unexpected child error %v", e)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || status.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", e, output)
			}
			r, e := generation.Open(filepath.Join(f.base, "replica"), f.authority.Trust, false)
			must(t, e)
			defer r.Close()
			f.options.Replica = r
			f.options.Initialize = false
			f.session, e = OpenSession(ctx, f.options)
			must(t, e)
			if f.session.state.Acknowledged {
				receipt := *f.session.state.Receipt
				ack, e := f.session.Acknowledge(ctx, receipt, 256)
				must(t, e)
				if !ack.Clean || ack.Receipt != receipt {
					t.Fatal("cleanup failed after kill", ack)
				}
				status, e := r.Status(ctx)
				must(t, e)
				if len(status.Pins) != 0 {
					t.Fatal("pin leaked after kill", status)
				}
				must(t, r.VerifyComplete(ctx, receipt.Generation))
				return
			}
			for id, b := range objects {
				_, e = f.session.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
				must(t, e)
			}
			var receipt Receipt
			for n := 0; n < 10; n++ {
				batch, result, e := f.session.FinishBatch(ctx, raw, 1, generation.MaxObject)
				must(t, e)
				if batch.Complete {
					receipt = result
					break
				}
			}
			if receipt.Generation != storage.Hash(raw) {
				t.Fatal("receipt lost after kill", receipt)
			}
			must(t, r.VerifyComplete(ctx, receipt.Generation))
		})
	}
}
