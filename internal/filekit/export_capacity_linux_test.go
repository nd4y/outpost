package filekit

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/statefile"
)

func TestExportPeakAdmissionRefusesBeforeDestinationAndPreservesKit(t *testing.T) {
	base, store, source, content := fixture(t, 2<<20)
	ctx := t.Context()
	version := mustBackup(t, store, source, BackupOptions{Names: []string{"file"}}).Version
	rootName := "versions/" + version + ".json"
	original, err := store.readFile(rootName, MaxRoot)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(base, "kit")
	refused := ExportOptions{MinFreeBytes: ^uint64(0)}
	if err = store.ExportWithOptions(ctx, version, destination, refused); !errors.Is(err, statefile.ErrCapacity) {
		t.Fatal("export did not refuse insufficient destination space", err)
	}
	if _, err = os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("capacity refusal created a destination", err)
	}
	if err = store.ExportWithOptions(ctx, version, filepath.Join(base, "store", "recursive-kit"), refused); !errors.Is(err, ErrInvalid) {
		t.Fatal("export did not reject a destination within its store", err)
	}
	if err = store.Export(ctx, version, destination); err != nil {
		t.Fatal("same destination could not be used after capacity refusal", err)
	}
	before, err := os.ReadFile(filepath.Join(destination, "kit.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.ExportWithOptions(ctx, version, destination, refused); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing completed destination was not refused", err)
	}
	after, err := os.ReadFile(filepath.Join(destination, "kit.json"))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("existing kit changed on attempted replacement", err)
	}
	retained, err := store.readFile(rootName, MaxRoot)
	if err != nil || !bytes.Equal(retained, original) {
		t.Fatal("source version root changed during export", err)
	}
	if _, err = store.VerifyVersion(ctx, version); err != nil {
		t.Fatal("source version ceased to be recoverable", err)
	}
	recovery := store.Owner
	recovery.SigningKey = nil
	kit, err := OpenStore(destination, recovery, false)
	if err != nil {
		t.Fatal(err)
	}
	defer kit.Close()
	mustRestore(t, kit, version, filepath.Join(base, "recovered"), content, true)
}

func TestExportPublicationDoesNotReplaceRacingDestination(t *testing.T) {
	base, store, source, original := fixture(t, 2<<20)
	ctx := t.Context()
	old := mustBackup(t, store, source, BackupOptions{Names: []string{"file"}})
	accepted := filepath.Join(base, "accepted")
	if err := store.Export(ctx, old.Version, accepted); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(accepted, "kit.json"))
	if err != nil {
		t.Fatal(err)
	}

	changed := append([]byte(nil), original...)
	changed[0] ^= 1
	if err = os.WriteFile(source, changed, 0600); err != nil {
		t.Fatal(err)
	}
	fresh := mustBackup(t, store, source, BackupOptions{Names: []string{"file"}, File: old.File, Previous: old.Version})
	destination := filepath.Join(base, "published")
	unknown := filepath.Join(base, ".outpost-kit-other")
	if err = os.WriteFile(unknown, []byte("unowned fixture entry"), 0600); err != nil {
		t.Fatal(err)
	}

	reached := false
	store.Fault = func(point string) error {
		if point != "export-before-publish" {
			return nil
		}
		reached = true
		if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("export exposed the destination before publication", err)
		}
		return os.Rename(accepted, destination)
	}
	if err = store.Export(ctx, fresh.Version, destination); !errors.Is(err, os.ErrExist) || !reached {
		t.Fatal("export failed to preserve the concurrent publisher", err)
	}
	after, err := os.ReadFile(filepath.Join(destination, "kit.json"))
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("concurrently published root changed", err)
	}
	marker, err := os.ReadFile(unknown)
	if err != nil || string(marker) != "unowned fixture entry" {
		t.Fatal("unrelated staging-prefix entry changed", err)
	}
	owner := store.Owner
	owner.SigningKey = nil
	winner, err := OpenStore(destination, owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer winner.Close()
	mustRestore(t, winner, old.Version, filepath.Join(base, "original-recovered"), original, true)
	store.Fault = nil
	retryDestination := filepath.Join(base, "retry")
	if err = store.Export(ctx, fresh.Version, retryDestination); err != nil {
		t.Fatal("fresh export after collision failed", err)
	}
	retry, err := OpenStore(retryDestination, owner, false)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Close()
	mustRestore(t, retry, fresh.Version, filepath.Join(base, "fresh-recovered"), changed, true)
}
