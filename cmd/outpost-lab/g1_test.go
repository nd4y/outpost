package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectExistingDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := newDirectory(dir); err == nil {
		t.Fatal("accepted existing directory")
	}
	if _, err := newDirectory(filepath.Join(dir, "new")); err != nil {
		t.Fatal(err)
	}
}

func TestDescriptorRejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	d := descriptor{"v1", "fixture/confidential-name.bin", strings.Repeat("a", 64), activeFixture.corpus, strings.Repeat("b", 64), 0600, 1700000001}
	if err := validDescriptor(d); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*descriptor){func(d *descriptor) { d.Version = "../escape" }, func(d *descriptor) { d.Path = "../../etc/passwd" }, func(d *descriptor) { d.Bytes++ }, func(d *descriptor) { d.Mode = 0777 }, func(d *descriptor) { d.Payload = "latest" }, func(d *descriptor) { d.SHA256 = "" }} {
		bad := d
		mutate(&bad)
		if validDescriptor(bad) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestPayloadBounds(t *testing.T) {
	var b bytes.Buffer
	s := payloadSink{&b, 3}
	if n, err := s.Write([]byte("ab")); n != 2 || err != nil {
		t.Fatal(n, err)
	}
	if _, err := s.Write([]byte("cd")); err == nil {
		t.Fatal("accepted overrun")
	}
	if b.String() != "ab" || s.remaining != 1 {
		t.Fatal("overrun changed state")
	}
}

func TestBackupSummaryRequiresFullID(t *testing.T) {
	if _, err := summaryID([]byte(`{"message_type":"summary","snapshot_id":"abc"}`)); err == nil {
		t.Fatal("accepted truncated ID")
	}
	id := strings.Repeat("a", 64)
	got, err := summaryID([]byte(`{"message_type":"status"}` + "\n" + `{"message_type":"summary","snapshot_id":"` + id + `"}`))
	if err != nil || got != id {
		t.Fatal(got, err)
	}
}
