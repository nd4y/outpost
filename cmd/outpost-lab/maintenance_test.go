package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestRetirementPreservesSharedPayload(t *testing.T) {
	remaining := map[string]catalogEntry{"v2": {Descriptor: descriptor{Payload: "shared"}}}
	got := unreferencedPayloads([]string{"shared", "orphan", "old", "orphan"}, remaining)
	if !slices.Equal(got, []string{"old", "orphan"}) {
		t.Fatalf("unsafe garbage plan: %v", got)
	}
	if got = unreferencedPayloads([]string{"shared"}, remaining); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestFixtureCloneIsIndependentAndRejectsRecursion(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(source, "pack")
	if err := os.WriteFile(pack, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cloneFixture(source, filepath.Join(source, "nested")); err == nil {
		t.Fatal("recursive copy accepted")
	}
	dest := filepath.Join(root, "copy")
	if err := cloneFixture(source, dest); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "pack"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pack)
	if err != nil || string(got) != "original" {
		t.Fatalf("source changed: %q %v", got, err)
	}
	if err := cloneFixture(source, dest); err == nil {
		t.Fatal("existing destination accepted")
	}
}

func TestFixtureCloneRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root, filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := cloneFixture(source, filepath.Join(root, "copy")); err == nil {
		t.Fatal("symlink accepted")
	}
}
