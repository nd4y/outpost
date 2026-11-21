package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/nd4y/outpost/internal/recoverybundle"
)

func TestCLIOwnerRecoveryPackageContractAndRedactedErrors(t *testing.T) {
	help, e := run(context.Background(), []string{"help"})
	if e != nil {
		t.Fatal(e)
	}
	commands := help.(map[string]any)["commands"].([]string)
	for _, want := range []string{"source-recovery-export ", "recovery-package-inspect ", "recovery-package-extract "} {
		found := false
		for _, command := range commands {
			found = found || strings.HasPrefix(command, want)
		}
		if !found {
			t.Fatal("missing owner command", want)
		}
	}
	version, e := run(context.Background(), []string{"version"})
	if e != nil || version.(map[string]any)["ownerRecoveryPackage"] != recoverybundle.Format {
		t.Fatal("missing format admission", e)
	}
	for _, test := range []struct {
		err    error
		code   string
		status int
	}{{recoverybundle.ErrInvalid, "INCOMPLETE_OR_CORRUPT", 4}, {recoverybundle.ErrDenied, "DENIED", 3}, {recoverybundle.ErrConflict, "CONFLICT", 5}, {recoverybundle.ErrCapacity, "CAPACITY_BLOCKED", 6}} {
		code, status := failure(errors.Join(test.err, &os.PathError{Op: "open", Path: "/private/secret-source-name", Err: os.ErrNotExist}))
		if code != test.code || status != test.status {
			t.Fatal("owner package error mapping", code, status)
		}
	}
	if _, e = run(context.Background(), []string{"recovery-package-inspect", "--input", "relative-secret", "--sha256", strings.Repeat("a", 64)}); e == nil {
		t.Fatal("relative package accepted")
	}
}
