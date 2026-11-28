package filekit

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/nd4y/outpost/internal/teststore"
	"os"
	"path/filepath"
	"testing"
)

func TestFrozenV1KitCreatedByPreviousImplementation(t *testing.T) {
	base, e := filepath.Abs("testdata/v1")
	entryOK(t, e)
	var owner Owner
	raw := teststore.PublicV1Owner()
	entryOK(t, json.Unmarshal(raw, &owner))
	var fixture struct {
		Version, Content, SHA256, ProducerCommit string
		TestOnly                                 bool
	}
	raw, e = os.ReadFile(filepath.Join(base, "manifest.fixture"))
	entryOK(t, e)
	entryOK(t, json.Unmarshal(raw, &fixture))
	if !fixture.TestOnly || fixture.ProducerCommit != "3193619e23a532041ad5b75376d052fb1306247b" || len(owner.SigningKey) != 0 {
		t.Fatal("not the frozen public recovery-only reference")
	}
	kit := filepath.Join(t.TempDir(), "kit")
	entryOK(t, os.CopyFS(kit, os.DirFS(filepath.Join(base, "kit"))))
	entryOK(t, os.Rename(filepath.Join(kit, "root.fixture"), filepath.Join(kit, "kit.json")))
	store, e := OpenStore(kit, owner, false)
	entryOK(t, e)
	defer store.Close()
	d, e := store.VerifyKit(context.Background(), fixture.Version)
	entryOK(t, e)
	var output bytes.Buffer
	entryOK(t, store.readTo(context.Background(), d, &output))
	if d.Format != Format || d.Kind != "" || d.LinkTarget != "" || output.String() != fixture.Content || digest(output.Bytes()) != fixture.SHA256 || len(d.Names) != 2 || d.Names[0] != "dataset/старый файл.txt" {
		t.Fatal("old fixture changed or unreadable")
	}
}
