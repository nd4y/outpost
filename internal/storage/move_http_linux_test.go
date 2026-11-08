package storage

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/teststore"
)

func moveBackend(t *testing.T, s *teststore.Server) (*Backend, MoveBookOptions) {
	t.Helper()
	_, options := moveBookFixture(t)
	options.Profile = profile(s)
	options.Profile.WriteMode = WebDAVMoveMode
	options.Profile.MaxStagingAttempts = 3
	b, err := New(options.Profile, Credentials{Access: "test-worker", Secret: "ephemeral-test-secret", ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	return b, options
}

func TestWebDAVMoveLostRepliesResumeOwnedStage(t *testing.T) {
	var dropPut, dropMove atomic.Bool
	var destination atomic.Value
	s := teststore.New(t, teststore.Options{Kind: "webdav", MoveOnly: true, Namespace: Hash([]byte("move-lost-reply")), AfterWrite: func(w http.ResponseWriter, r *http.Request, _, key string, data []byte) bool {
		if r.Method == "PUT" && len(data) == 8192 && dropPut.CompareAndSwap(true, false) {
			w.WriteHeader(503)
			return true
		}
		if r.Method == "MOVE" && strings.HasPrefix(key, "part-") && dropMove.CompareAndSwap(true, false) {
			destination.Store(r.Header.Get("Destination"))
			w.WriteHeader(503)
			return true
		}
		return false
	}})
	b, options := moveBackend(t, s)
	book := openMoveTest(t, options)
	ctx := WithWriteAttempts(context.Background(), book)
	if err := b.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte{71}, 8192)
	key := "part-" + Hash(data)
	dropPut.Store(true)
	if err := b.Put(ctx, key, data); !errors.Is(err, ErrUnavailable) {
		t.Fatal("staging write was replayed after uncertain reply", err)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatal("destination appeared before MOVE", err)
	}
	if err := book.Close(); err != nil {
		t.Fatal(err)
	}
	options.Initialize = false
	book = openMoveTest(t, options)
	defer book.Close()
	ctx = WithWriteAttempts(context.Background(), book)
	dropMove.Store(true)
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal("lost MOVE reply was not settled by readback", err)
	}
	if got := destination.Load(); got != b.resourceURL(key) {
		t.Fatal("unexpected MOVE destination", got)
	}
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(ctx, key, bytes.Repeat([]byte{72}, len(data))); !errors.Is(err, ErrConflict) {
		t.Fatal("canonical object was replaceable", err)
	}
	if err := book.WithRecord(ctx, b.profile.ID(), key, Hash(data), len(data), func(tx MoveTransaction) error {
		attempts := tx.State().Attempts
		if len(attempts) != 1 || attempts[0].Phase != "PUBLISHED" {
			t.Fatal("lost reply generated extra staging objects", attempts)
		}
		temporary, err := tx.Temporary(attempts[0])
		if err != nil {
			return err
		}
		writes := s.Snapshot().Writes
		if writes[key] != 1 || writes[temporary] != 1 {
			t.Fatal("object was rewritten", writes[key], writes[temporary])
		}
		if _, err = os.Stat(s.Path(temporary)); !os.IsNotExist(err) {
			t.Fatal("fixture did not move the staged object", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWebDAVMoveRejectsFalsePublicationAndUnsafeRequests(t *testing.T) {
	var fake atomic.Bool
	var redirect atomic.Bool
	s := teststore.New(t, teststore.Options{Kind: "webdav", MoveOnly: true, Namespace: Hash([]byte("false-move")), Before: func(w http.ResponseWriter, r *http.Request, _, _ string, _ []byte) bool {
		if redirect.Load() && r.Method == "MOVE" {
			w.Header().Set("Location", "/different-namespace/unsupported")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return true
		}
		if fake.Load() && r.Method == "MOVE" {
			w.WriteHeader(201)
			return true
		}
		return false
	}})
	b, options := moveBackend(t, s)
	book := openMoveTest(t, options)
	defer book.Close()
	ctx := WithWriteAttempts(context.Background(), book)
	if err := b.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	data := []byte("manifest fixture")
	key := "complete-" + Hash(data)
	fake.Store(true)
	if err := b.Put(ctx, key, data); !errors.Is(err, ErrUnavailable) {
		t.Fatal("accepted false MOVE success", err)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatal("false MOVE published a marker", err)
	}
	before := s.Snapshot().Requests
	temporary := "attempt-" + Hash(data)
	for _, pair := range [][2]string{{temporary, "https://other.invalid/path"}, {temporary, "../path"}, {key, temporary}, {key, "layout"}} {
		if _, err := b.move(ctx, pair[0], pair[1]); !errors.Is(err, ErrDenied) {
			t.Fatal("unsafe MOVE accepted", pair, err)
		}
	}
	if err := b.Put(context.Background(), key, data); !errors.Is(err, ErrDenied) {
		t.Fatal("write without attempt book admitted", err)
	}
	if _, _, err := b.request(ctx, http.MethodPut, key, data); !errors.Is(err, ErrDenied) {
		t.Fatal("canonical PUT admitted by transport", err)
	}
	if s.Snapshot().Requests != before {
		t.Fatal("unsafe requests reached endpoint")
	}
	fake.Store(false)
	redirect.Store(true)
	if err := b.Put(ctx, key, data); !errors.Is(err, ErrUnsupported) {
		t.Fatal("redirected MOVE accepted", err)
	}
	redirect.Store(false)
	if err := b.Put(ctx, key, data); err != nil {
		t.Fatal("verified staging could not resume", err)
	}
	before = s.Snapshot().Requests
	b.credentials.ExpiresUnix = time.Now().Unix() - 1
	if err := b.Put(ctx, "layout-other", data); !errors.Is(err, ErrDenied) {
		t.Fatal("expired credential used for a new attempt", err)
	}
	if s.Snapshot().Requests != before {
		t.Fatal("expired credential reached endpoint")
	}
}

func TestWebDAVMoveRetainsCorruptStagesAndBoundsRetries(t *testing.T) {
	directory := teststore.Root(t)
	namespace := Hash([]byte("corrupt-staging"))
	s := teststore.New(t, teststore.Options{Kind: "webdav", MoveOnly: true, Directory: directory, Namespace: namespace, AfterWrite: func(w http.ResponseWriter, r *http.Request, _, key string, data []byte) bool {
		if r.Method == http.MethodPut && len(data) == 8192 {
			if err := os.WriteFile(filepath.Join(directory, namespace+"-"+key), data[:7], 0600); err != nil {
				w.WriteHeader(500)
				return true
			}
		}
		return false
	}})
	b, options := moveBackend(t, s)
	b.profile.TimeoutMillis = 400
	b.profile.MaxStagingAttempts = 2
	options.Profile = b.profile
	book := openMoveTest(t, options)
	defer book.Close()
	ctx := WithWriteAttempts(context.Background(), book)
	data := bytes.Repeat([]byte{7}, 8192)
	key := "part-" + Hash(data)
	for i := 0; i < b.profile.MaxStagingAttempts; i++ {
		if err := b.Put(ctx, key, data); !errors.Is(err, ErrUnavailable) {
			t.Fatal("corrupt stage accepted", err)
		}
		time.Sleep(time.Duration(b.profile.TimeoutMillis) * time.Millisecond)
	}
	if err := b.Put(ctx, key, data); !errors.Is(err, ErrCapacity) {
		t.Fatal("staging budget exceeded", err)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatal("corrupt ciphertext reached canonical name", err)
	}
	writes := s.Snapshot().Writes
	if len(writes) != 2 {
		t.Fatal("unexpected number of written stages", len(writes))
	}
	for name, count := range writes {
		got, err := os.ReadFile(s.Path(name))
		if err != nil || !strings.HasPrefix(name, "attempt-") || count != 1 || !bytes.Equal(got, data[:7]) {
			t.Fatal("previous uncertain stage was changed or lost", name, count, err)
		}
	}
}

func TestWebDAVMoveProbeRefusesIgnoredOverwrite(t *testing.T) {
	s := teststore.New(t, teststore.Options{Kind: "webdav", MoveOnly: true, IgnoreMoveOverwrite: true, Namespace: Hash([]byte("unsafe-move"))})
	b, options := moveBackend(t, s)
	book := openMoveTest(t, options)
	defer book.Close()
	if err := b.Probe(WithWriteAttempts(context.Background(), book)); !errors.Is(err, ErrUnsupported) {
		t.Fatal("ignored Overwrite:F admitted", err)
	}
	if _, err := os.Stat(s.Path("layout")); !os.IsNotExist(err) {
		t.Fatal("unsafe probe admitted layout", err)
	}
}
