package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func publicationFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	ok(t, filepath.WalkDir(dir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		name, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		out[name] = Hash(raw)
		return nil
	}))
	return out
}

func TestPublishedEvidenceKeepsOriginalTimeAndDoesNotWrite(t *testing.T) {
	base := temp(t)
	trust, key, _ := trust(t)
	dir := filepath.Join(base, "replica")
	r := openTest(t, dir, trust)
	raw, objects := synthetic(t, trust, key, 1, "historical publication")
	first, e := r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects))
	ok(t, e)
	if !first.Complete {
		t.Fatal("fixture incomplete")
	}
	before := publicationFiles(t, dir)
	r.Admit = func(string, int) (func(bool) error, error) {
		t.Fatal("read-only evidence attempted a write")
		return nil, ErrInvalid
	}
	proof, e := r.PublishedEvidence(ctx, Hash(raw))
	ok(t, e)
	if proof.Generation != first.Generation || proof.VerifiedAt != first.VerifiedAt || proof.Objects != 2 || proof.Bytes != first.ReadBytes || !validID(proof.Verification) {
		t.Fatal("wrong historical proof", proof, first)
	}
	time.Sleep(1100 * time.Millisecond)
	second, e := r.PublishedEvidence(ctx, Hash(raw))
	ok(t, e)
	if second != proof {
		t.Fatal("reading refreshed original evidence", proof, second)
	}
	if !reflect.DeepEqual(before, publicationFiles(t, dir)) {
		t.Fatal("evidence lookup changed durable files")
	}
}

func TestPublishedEvidenceRejectsMissingChangedAndIncompleteProofWithoutWriting(t *testing.T) {
	for _, kind := range []string{"missing-verification", "incomplete-verification", "corrupt-verification", "changed-object", "missing-object", "corrupt-catalog", "unpublished", "damaged", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			base := temp(t)
			trust, key, _ := trust(t)
			dir := filepath.Join(base, "replica")
			r := openTest(t, dir, trust)
			raw, objects := synthetic(t, trust, key, 1, "proof rejection")
			id := Hash(raw)
			_, e := r.ReceiveBatch(ctx, raw, 2, MaxObject, fetch(objects))
			ok(t, e)
			refs, e := Dependencies(raw, trust)
			ok(t, e)
			proofPath := filepath.Join(dir, "verification", id)
			switch kind {
			case "missing-verification":
				ok(t, os.Remove(proofPath))
			case "incomplete-verification":
				b, e := os.ReadFile(proofPath)
				ok(t, e)
				var v verificationState
				ok(t, json.Unmarshal(b, &v))
				v.CompletedAt = 0
				b, e = json.Marshal(v)
				ok(t, e)
				ok(t, os.WriteFile(proofPath, b, 0600))
			case "corrupt-verification":
				ok(t, os.WriteFile(proofPath, []byte("{}"), 0600))
			case "changed-object":
				path := filepath.Join(dir, "objects", refs[0].ID)
				i, e := os.Stat(path)
				ok(t, e)
				b := bytes.Clone(objects[refs[0].ID])
				b[0] ^= 1
				ok(t, os.WriteFile(path, b, 0600))
				ok(t, os.Chtimes(path, i.ModTime(), i.ModTime()))
			case "missing-object":
				ok(t, os.Remove(filepath.Join(dir, "objects", refs[0].ID)))
			case "corrupt-catalog":
				ok(t, os.WriteFile(filepath.Join(dir, "catalogs", id), []byte("{}"), 0600))
			case "unpublished":
				ok(t, r.exclusive(ctx, func() error {
					s, e := r.load()
					if e != nil {
						return e
					}
					item := s.Generations[id]
					item.Complete = false
					s.Generations[id] = item
					s.Latest = ""
					return r.save(s)
				}))
			case "damaged":
				ok(t, r.exclusive(ctx, func() error {
					s, e := r.load()
					if e != nil {
						return e
					}
					return r.recordCatalogDamage(&s, id)
				}))
			}
			before := publicationFiles(t, dir)
			r.Admit = func(string, int) (func(bool) error, error) {
				t.Fatal("failed historical lookup attempted write")
				return nil, ErrInvalid
			}
			check := ctx
			if kind == "cancelled" {
				var cancel context.CancelFunc
				check, cancel = context.WithCancel(ctx)
				cancel()
			}
			proof, e := r.PublishedEvidence(check, id)
			if e == nil || proof != (PublicationEvidence{}) {
				t.Fatal("unsupported historical proof accepted", kind, proof, e)
			}
			if kind == "cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("wrong cancellation", e)
			}
			if !reflect.DeepEqual(before, publicationFiles(t, dir)) {
				t.Fatal("rejection modified durable files", kind)
			}
		})
	}
}
