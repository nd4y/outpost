package generation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/localfs"
)

func TestRecoveryDestinationCannotContainOrEnterReplica(t *testing.T) {
	base := temp(t)
	tt, _, _ := trust(t)
	replica := openTest(t, filepath.Join(base, "replica"), tt)
	defer replica.Close()
	parent, e := os.OpenRoot(base)
	ok(t, e)
	defer parent.Close()
	if e = replica.CheckRecoveryDestination(ctx, parent); !errors.Is(e, localfs.ErrBoundary) {
		t.Fatal("replica nested inside plaintext output", e)
	}
	ok(t, replica.root.Mkdir("nested", 0700))
	nested, e := replica.root.OpenRoot("nested")
	ok(t, e)
	defer nested.Close()
	if e = replica.CheckRecoveryDestination(ctx, nested); !errors.Is(e, localfs.ErrBoundary) {
		t.Fatal("plaintext nested inside replica", e)
	}
	ok(t, os.Mkdir(filepath.Join(base, "separate"), 0700))
	separate, e := os.OpenRoot(filepath.Join(base, "separate"))
	ok(t, e)
	defer separate.Close()
	ok(t, replica.CheckRecoveryDestination(ctx, separate))
}
