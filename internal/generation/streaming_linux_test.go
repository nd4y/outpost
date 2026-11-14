package generation

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/filekit"
)

type ingressObjects struct {
	data      map[string][]byte
	readable  map[string]bool
	readBytes int
}

func (b *ingressObjects) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if b.readable != nil && !b.readable[ref.ID] {
		return nil, ErrInvalid
	}
	data, ok := b.data[ref.ID]
	if !ok {
		return nil, os.ErrNotExist
	}
	b.readBytes += len(data)
	return append([]byte(nil), data...), nil
}
func (b *ingressObjects) Write(ctx context.Context, ref filekit.Object, data []byte) (bool, error) {
	if e := ctx.Err(); e != nil {
		return false, e
	}
	if ref.ID != Hash(data) || ref.Bytes != len(data) {
		return false, ErrInvalid
	}
	if old, ok := b.data[ref.ID]; ok {
		if !bytes.Equal(old, data) {
			return false, ErrConflict
		}
		return false, nil
	}
	b.data[ref.ID] = append([]byte(nil), data...)
	return true, nil
}
func (b *ingressObjects) Check(ctx context.Context, ref filekit.Object) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if data, ok := b.data[ref.ID]; !ok {
		return os.ErrNotExist
	} else if len(data) != ref.Bytes {
		return ErrInvalid
	}
	return nil
}
func TestBuildCatalogDoesNotFetchPayloadBackThroughSource(t *testing.T) {
	base := temp(t)
	owner, e := filekit.NewOwner()
	ok(t, e)
	trust, writer, _ := trust(t)
	trust.Domain = owner.Domain
	ingress := &ingressObjects{data: map[string][]byte{}}
	cache := filepath.Join(base, "cache")
	source, e := filekit.OpenStreamingStore(cache, owner, true, ingress)
	ok(t, e)
	input := filepath.Join(base, "input")
	content := bytes.Repeat([]byte("known synthetic source\n"), 100000)
	ok(t, os.WriteFile(input, content, 0640))
	result, e := source.Backup(ctx, input, filekit.BackupOptions{Names: []string{"original/file"}})
	ok(t, e)
	envelope, _, e := source.LoadVersion(result.Version)
	ok(t, e)
	ingress.readable = map[string]bool{}
	for _, part := range envelope.Parts {
		ingress.readable[part.ID] = true
	}
	ingress.readBytes = 0
	raw, roots, e := BuildCatalog(ctx, source, []string{result.Version}, Catalog{Format: Format, Domain: trust.Domain, Repository: trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: 1, Policy: 1}, writer)
	ok(t, e)
	if ingress.readBytes > 65536 || len(roots) != 1 {
		t.Fatal("catalog construction downloaded payload", ingress.readBytes)
	}
	receiver := openTest(t, filepath.Join(base, "receiver"), trust)
	id, e := receiver.Receive(ctx, raw, func(ref Object) ([]byte, error) {
		if data, ok := roots[ref.ID]; ok {
			return data, nil
		}
		data, ok := ingress.data[ref.ID]
		if !ok {
			return nil, os.ErrNotExist
		}
		return data, nil
	})
	ok(t, e)
	ok(t, source.Close())
	ok(t, os.RemoveAll(cache))
	ok(t, os.Remove(input))
	ingress.data = nil
	kit := filepath.Join(base, "independent")
	ok(t, receiver.ExportKit(ctx, id, result.Version, kit))
	owner.SigningKey = nil
	reader, e := filekit.OpenStore(kit, owner, false)
	ok(t, e)
	defer reader.Close()
	output := filepath.Join(base, "restore")
	d, e := reader.Restore(ctx, result.Version, output)
	ok(t, e)
	restored, e := os.ReadFile(filepath.Join(output, d.Names[0]))
	ok(t, e)
	if !bytes.Equal(restored, content) {
		t.Fatal("streamed generation not independently recoverable")
	}
}
