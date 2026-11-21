package ingress

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

func TestAcknowledgementReleasesOnlyOwnCopiesAndPreservesReceipt(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"private/data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{v.Version})
	f.roots(t, roots)
	receipt, e := f.session.Finish(ctx, raw)
	must(t, e)
	foreign := storage.Hash([]byte("unrelated-reader"))
	must(t, f.options.Replica.Pin(ctx, foreign, receipt.Generation, "generation"))
	wrong := receipt
	wrong.VerifiedAt--
	if _, e = f.session.Acknowledge(ctx, wrong, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("foreign receipt released pin", e)
	}
	before, e := f.options.Replica.Status(ctx)
	must(t, e)
	if len(before.Pins) != 2 {
		t.Fatal("missing initial pins", before)
	}
	step, e := f.session.Acknowledge(ctx, receipt, 1)
	must(t, e)
	if step.Receipt != receipt || step.RemainingObjects != receipt.NewObjects-1 || step.Clean {
		t.Fatal("unbounded cleanup", step)
	}
	f.reopen(t)
	for n := 0; n < receipt.NewObjects; n++ {
		step, e = f.session.Acknowledge(ctx, receipt, 1)
		must(t, e)
		if step.Clean {
			break
		}
	}
	if !step.Clean || step.RemainingBytes != 0 || step.Receipt != receipt {
		t.Fatal("cleanup failed", step)
	}
	step, e = f.session.Acknowledge(ctx, receipt, 1)
	must(t, e)
	if !step.Clean || step.Receipt != receipt {
		t.Fatal("replay changed receipt", step)
	}
	after, e := f.options.Replica.Status(ctx)
	must(t, e)
	if len(after.Pins) != 1 || after.Pins[foreign].Generation != receipt.Generation || after.LatestComplete != receipt.Generation {
		t.Fatal("cleanup crossed ownership", after)
	}
	if _, e = f.session.Finish(ctx, raw); !errors.Is(e, ErrConflict) {
		t.Fatal("acked operation reopened", e)
	}
	for id, b := range roots {
		ref := filekit.Object{ID: id, Bytes: len(b)}
		if _, e = f.session.Read(ctx, ref); !errors.Is(e, ErrConflict) {
			t.Fatal("acked read accepted", e)
		}
		if _, e = f.session.Write(ctx, ref, b); !errors.Is(e, ErrConflict) {
			t.Fatal("acked write accepted", e)
		}
		if e = f.session.Check(ctx, ref); !errors.Is(e, ErrConflict) {
			t.Fatal("acked check accepted", e)
		}
	}
	out := filepath.Join(f.base, "after-ack")
	_, e = generation.RecoverMaterialized(ctx, filepath.Join(f.base, "replica"), receipt.Generation, f.authority.Trust, f.owner, generation.RecoverySelection{}, out)
	must(t, e)
	got, e := os.ReadFile(filepath.Join(out, "private/data"))
	must(t, e)
	if string(got) != string(f.payload) {
		t.Fatal("cleanup damaged published copy")
	}
}

func TestAcknowledgementRejectsSubstitutedStagingLink(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{v.Version})
	f.roots(t, roots)
	receipt, e := f.session.Finish(ctx, raw)
	must(t, e)
	for id := range f.session.refs {
		path := filepath.Join(f.options.Directory, "objects", id)
		must(t, os.Remove(path))
		must(t, os.Symlink(f.input, path))
		break
	}
	if _, e = f.session.Acknowledge(ctx, receipt, 256); !errors.Is(e, ErrConflict) {
		t.Fatal("substitution ignored", e)
	}
	got, e := os.ReadFile(f.input)
	must(t, e)
	if string(got) != string(f.payload) {
		t.Fatal("external path changed")
	}
	must(t, f.options.Replica.VerifyComplete(ctx, receipt.Generation))
}

func TestHTTPSAcknowledgementIsIdempotentAfterLostReply(t *testing.T) {
	f := network(t, nil)
	ctx := context.Background()
	v, e := f.source.Backup(ctx, f.input, filekit.BackupOptions{Names: []string{"data"}})
	must(t, e)
	raw, roots := f.catalog(t, []string{v.Version})
	for id, b := range roots {
		_, e = f.client.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b)
		must(t, e)
	}
	_, receipt, e := f.client.FinishStep(ctx, raw)
	must(t, e)
	if receipt == nil {
		t.Fatal("no receipt")
	}
	f.session.Fault = func(name string) error {
		if name == "capture-staged-object-removed" {
			return errors.New("lost reply")
		}
		return nil
	}
	if _, e = f.client.AcknowledgeStep(ctx, *receipt); e == nil {
		t.Fatal("fault absent")
	}
	f.session.Fault = nil
	ack, e := f.client.AcknowledgeStep(ctx, *receipt)
	must(t, e)
	if !ack.Clean || ack.Receipt != *receipt {
		t.Fatal("acknowledgement did not resume", ack)
	}
	_, _, e = f.client.FinishStep(ctx, raw)
	if !errors.Is(e, ErrConflict) {
		t.Fatal("closed capture reverified", e)
	}
}
