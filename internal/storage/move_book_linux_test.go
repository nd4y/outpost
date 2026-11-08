package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/teststore"
)

func moveBookFixture(t *testing.T) (string, MoveBookOptions) {
	t.Helper()
	base := teststore.Root(t)
	root, e := localfs.OpenRoot(base)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	p := Profile{Kind: "webdav", Endpoint: "https://example.invalid/objects/", Namespace: Hash([]byte("namespace")), MaxObjectBytes: 64 << 10, Concurrency: 2, RequestsPerSecond: 1000, Attempts: 3, TimeoutMillis: 1000, CredentialScope: "namespace", NoDelete: true, WriteMode: WebDAVMoveMode, MaxStagingAttempts: 3}
	return base, MoveBookOptions{Parent: root, Directory: "attempts", Scope: Hash([]byte("plan-worker-scope")), Profile: p, Initialize: true}
}
func openMoveTest(t *testing.T, o MoveBookOptions) *MoveBook {
	t.Helper()
	b, e := OpenMoveBook(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestMoveBookResumesExactAttemptAndBoundsRetainedUncertainty(t *testing.T) {
	_, o := moveBookFixture(t)
	b := openMoveTest(t, o)
	ctx := context.Background()
	key := "part-" + Hash([]byte("data"))
	digest := Hash([]byte("data"))
	var initial MoveAttempt
	var temporary string
	var escaped MoveTransaction
	e := b.WithRecord(ctx, o.Profile.ID(), key, digest, 4, func(tx MoveTransaction) error {
		escaped = tx
		var e error
		initial, e = tx.Allocate()
		if e != nil {
			return e
		}
		temporary, e = tx.Temporary(initial)
		if e != nil {
			return e
		}
		if !strings.HasPrefix(temporary, "attempt-") || !ID(strings.TrimPrefix(temporary, "attempt-")) {
			t.Fatal("unsafe staging name")
		}
		copy := tx.State()
		copy.Attempts[0].Nonce = Hash([]byte("substitute"))
		if tx.State().Attempts[0].Nonce != initial.Nonce {
			t.Fatal("mutable record escaped")
		}
		return tx.Transition(initial.Nonce, "WRITING")
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = escaped.Allocate(); !errors.Is(e, ErrConflict) {
		t.Fatal("transaction escaped lease", e)
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	o.Initialize = false
	b = openMoveTest(t, o)
	defer b.Close()
	e = b.WithRecord(ctx, o.Profile.ID(), key, digest, 4, func(tx MoveTransaction) error {
		r := tx.State()
		if len(r.Attempts) != 1 || r.Attempts[0].Nonce != initial.Nonce || r.Attempts[0].Phase != "WRITING" {
			t.Fatal("uncertain attempt replaced", r)
		}
		name, e := tx.Temporary(r.Attempts[0])
		if e != nil || name != temporary {
			t.Fatal("staging identity changed", e)
		}
		if _, e = tx.Allocate(); !errors.Is(e, ErrConflict) {
			t.Fatal("active attempt duplicated", e)
		}
		if e = tx.Transition(initial.Nonce, "STAGED"); e != nil {
			return e
		}
		if e = tx.Transition(initial.Nonce, "PUBLISHED"); e != nil {
			return e
		}
		if e = tx.Transition(initial.Nonce, "WRITING"); !errors.Is(e, ErrConflict) {
			t.Fatal("published attempt rolled back", e)
		}
		for n := 0; n < 2; n++ {
			a, e := tx.Allocate()
			if e != nil {
				return e
			}
			name, e := tx.Temporary(a)
			if e != nil || name == temporary {
				t.Fatal("attempt name reused", e)
			}
			if e = tx.Transition(a.Nonce, "WRITING"); e != nil {
				return e
			}
			if e = tx.Transition(a.Nonce, "ABANDONED"); e != nil {
				return e
			}
		}
		if _, e = tx.Allocate(); !errors.Is(e, ErrCapacity) {
			t.Fatal("uncertain attempt bound bypassed", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	called := false
	e = b.WithRecord(ctx, o.Profile.ID(), key, Hash([]byte("evil")), 4, func(MoveTransaction) error { called = true; return nil })
	if !errors.Is(e, ErrConflict) || called {
		t.Fatal("same canonical key changed bytes", e)
	}
}
func TestMoveBookMissingInitializedBucketAndBindingNeverRecreated(t *testing.T) {
	base, o := moveBookFixture(t)
	b := openMoveTest(t, o)
	ctx := context.Background()
	key := "layout"
	digest := Hash([]byte("a"))
	if e := b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(tx MoveTransaction) error { _, e := tx.Allocate(); return e }); e != nil {
		t.Fatal(e)
	}
	b.Close()
	path := filepath.Join(base, o.Directory, "bucket-"+Hash([]byte(key))[:3]+".json")
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	o.Initialize = false
	b = openMoveTest(t, o)
	defer b.Close()
	called := false
	if e := b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(MoveTransaction) error { called = true; return nil }); e == nil || called {
		t.Fatal("lost bucket recreated", e)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("lost history reappeared", e)
	}
	wrong := o
	wrong.Scope = Hash([]byte("other-worker"))
	if other, e := OpenMoveBook(ctx, wrong); e == nil {
		other.Close()
		t.Fatal("book scope rebound")
	}
	wrong = o
	wrong.Profile.MaxStagingAttempts++
	if other, e := OpenMoveBook(ctx, wrong); e == nil {
		other.Close()
		t.Fatal("book profile rebound")
	}
	if e := os.Remove(filepath.Join(base, o.Directory, "book.json")); e != nil {
		t.Fatal(e)
	}
	if other, e := OpenMoveBook(ctx, o); e == nil {
		other.Close()
		t.Fatal("lost book silently initialized")
	}
}
func TestMoveBookInitializationFaultsPreserveIntentAndQuotaRefusal(t *testing.T) {
	for _, point := range []string{"move-bucket-intent", "move-bucket-created", "move-bucket-ready", "move-attempt-allocated", "move-attempt-writing"} {
		t.Run(point, func(t *testing.T) {
			_, o := moveBookFixture(t)
			b := openMoveTest(t, o)
			ctx := context.Background()
			b.o.Fault = func(p string) error {
				if p == point {
					return errors.New("lost metadata reply")
				}
				return nil
			}
			key := "part-" + Hash([]byte("capture"))
			digest := Hash([]byte("x"))
			e := b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(tx MoveTransaction) error {
				a, e := tx.Allocate()
				if e != nil {
					return e
				}
				return tx.Transition(a.Nonce, "WRITING")
			})
			if e == nil {
				t.Fatal("fault absent")
			}
			b.Close()
			o.Initialize = false
			b = openMoveTest(t, o)
			defer b.Close()
			e = b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(tx MoveTransaction) error {
				r := tx.State()
				if len(r.Attempts) == 0 {
					_, e := tx.Allocate()
					return e
				}
				if len(r.Attempts) != 1 {
					t.Fatal("metadata fault duplicated attempt")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
	_, o := moveBookFixture(t)
	o.Admission = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if b, e := OpenMoveBook(context.Background(), o); !errors.Is(e, statefile.ErrCapacity) {
		if b != nil {
			b.Close()
		}
		t.Fatal("capacity ignored", e)
	}
	o.Admission = nil
	o.Guard = func(context.Context) error { return ErrDenied }
	if b, e := OpenMoveBook(context.Background(), o); !errors.Is(e, ErrDenied) {
		if b != nil {
			b.Close()
		}
		t.Fatal("volume/authority guard ignored", e)
	}
}
func TestMoveBookRejectsClockRollbackAndProfileDowngrade(t *testing.T) {
	base, o := moveBookFixture(t)
	b := openMoveTest(t, o)
	ctx := context.Background()
	key := "complete-" + Hash([]byte("catalog"))
	digest := Hash([]byte("z"))
	if e := b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(tx MoveTransaction) error { _, e := tx.Allocate(); return e }); e != nil {
		t.Fatal(e)
	}
	b.Close()
	path := filepath.Join(base, o.Directory, "bucket-"+Hash([]byte(key))[:3]+".json")
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var bucket moveBucket
	if e = json.Unmarshal(raw, &bucket); e != nil {
		t.Fatal(e)
	}
	id := Hash([]byte(key))
	r := bucket.Records[id]
	r.UpdatedUnix = time.Now().Unix() + 3600
	bucket.Records[id] = r
	raw, _ = json.Marshal(bucket)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	o.Initialize = false
	b = openMoveTest(t, o)
	defer b.Close()
	if e = b.WithRecord(ctx, o.Profile.ID(), key, digest, 1, func(MoveTransaction) error { return nil }); e == nil {
		t.Fatal("future metadata accepted")
	}
	for _, kind := range []string{"unknown", "s3", "zero-bound", "excess-bound", "legacy-bound"} {
		p := o.Profile
		switch kind {
		case "unknown":
			p.WriteMode = "unknown"
		case "s3":
			p.Kind = "s3"
			p.Region = "test"
		case "zero-bound":
			p.MaxStagingAttempts = 0
		case "excess-bound":
			p.MaxStagingAttempts = 9
		case "legacy-bound":
			p.WriteMode = ""
		}
		if p.Validate() == nil {
			t.Fatal("invalid write mode accepted", kind)
		}
	}
	p := o.Profile
	p.WriteMode = ""
	p.MaxStagingAttempts = 0
	raw, _ = json.Marshal(p)
	if strings.Contains(string(raw), "writeMode") || strings.Contains(string(raw), "maxStagingAttempts") || p.Validate() != nil {
		t.Fatal("legacy canonical profile changed")
	}
}
