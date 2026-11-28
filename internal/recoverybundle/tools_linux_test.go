package recoverybundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/storage"
)

func TestRecoveryPackageRejectsSelectedToolsWithUnsafeSemantics(t *testing.T) {
	for _, kind := range []string{"wrong-machine", "invalid-elf-version", "dynamic-interpreter", "symlink", "duplicate", "extra-gzip-member", "extra-padding", "duplicate-manifest-key", "unknown-manifest-key", "wrong-source-digest", "wrong-development-revision"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			manifestPath := filepath.Join(f.options.ToolsDirectory, "manifest.json")
			raw, e := os.ReadFile(manifestPath)
			must(t, e)
			var m toolManifest
			must(t, json.Unmarshal(raw, &m))
			archivePath := filepath.Join(f.options.ToolsDirectory, "outpost-linux-amd64.tar.gz")
			original, e := os.ReadFile(archivePath)
			must(t, e)
			var changed bytes.Buffer
			z := gzip.NewWriter(&changed)
			w := tar.NewWriter(z)
			input, e := gzip.NewReader(bytes.NewReader(original))
			must(t, e)
			r := tar.NewReader(input)
			for {
				h, e := r.Next()
				if e == io.EOF {
					break
				}
				must(t, e)
				data, e := io.ReadAll(r)
				must(t, e)
				if h.Name == "outpost" && (kind == "wrong-machine" || kind == "invalid-elf-version" || kind == "dynamic-interpreter") {
					if kind == "wrong-machine" {
						binary.LittleEndian.PutUint16(data[18:], 183)
					} else if kind == "invalid-elf-version" {
						data[6] = 2
					} else {
						binary.LittleEndian.PutUint32(data[64:], 3)
					}
					m.Files["linux_amd64/outpost"] = File{storage.Hash(data), int64(len(data))}
				}
				if h.Name == "outpost-kit" {
					if kind == "duplicate" {
						h.Name = "outpost"
					}
					if kind == "symlink" {
						h.Typeflag = tar.TypeSymlink
						h.Linkname = "/bin/sh"
						data = nil
						h.Size = 0
					}
				}
				must(t, w.WriteHeader(h))
				_, e = w.Write(data)
				must(t, e)
			}
			must(t, input.Close())
			must(t, w.Close())
			if kind == "extra-padding" {
				_, e = z.Write(make([]byte, 11000))
				must(t, e)
			}
			must(t, z.Close())
			archive := changed.Bytes()
			if kind == "extra-gzip-member" {
				archive = append(archive, original...)
			}
			m.Files["outpost-linux-amd64.tar.gz"] = File{storage.Hash(archive), int64(len(archive))}
			must(t, os.WriteFile(archivePath, archive, 0600))
			if kind == "wrong-source-digest" {
				m.SourceDigest = storage.Hash([]byte("unrelated-source"))
			}
			if kind == "wrong-development-revision" {
				m.Revision = "dev-" + storage.Hash([]byte("unrelated-source"))
				f.options.Revision = m.Revision
			}
			raw = encoded(t, m)
			if kind == "duplicate-manifest-key" {
				raw = append([]byte(`{"format":"outpost-distribution-1",`), raw[1:]...)
			}
			if kind == "unknown-manifest-key" {
				raw = append([]byte(`{"unsafe":true,`), raw[1:]...)
			}
			must(t, os.WriteFile(manifestPath, raw, 0600))
			f.options.ManifestSHA256 = storage.Hash(raw)
			if _, e = Export(context.Background(), f.material, f.options, filepath.Join(f.ownerDir, "rejected.tar")); e == nil {
				t.Fatal("unsafe selected tool accepted")
			}
			entries, e := os.ReadDir(f.ownerDir)
			must(t, e)
			if len(entries) != 0 {
				t.Fatal("wrote owner secrets before tool admission")
			}
		})
	}
}
