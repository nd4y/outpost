package worker

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/nd4y/outpost/internal/upload"
)

func TestExternalQueueWindowPreservesLegacyAndKnownLongIdentity(t *testing.T) {
	f := newFixture(t)
	authority := upload.Authority{Generation: f.domain.Trust, Planner: f.domain.Planner}
	node := f.nodes[0].node
	for _, long := range []bool{false, true} {
		name, window := "legacy", int64(0)
		if long {
			name, window = "long", upload.MaxAttemptMillis
		}
		dir := filepath.Join(f.base, name+"-queue")
		must(t, os.Mkdir(dir, 0700))
		q, err := openExternalQueue(nil, dir, node, authority, true, window, nil)
		must(t, err)
		state, err := q.Status(t.Context())
		must(t, err)
		must(t, q.Close())
		before, err := os.ReadFile(filepath.Join(dir, "queue.json"))
		must(t, err)
		for _, currentWindow := range []int64{0, upload.MaxAttemptMillis} {
			q, err = openExternalQueue(nil, dir, node, authority, false, currentWindow, nil)
			must(t, err)
			current, err := q.Status(t.Context())
			must(t, err)
			must(t, q.Close())
			if current.Identity != state.Identity || current.Instance != state.Instance || current.Revision != state.Revision {
				t.Fatal("current configuration silently rebound retained queue resources")
			}
		}
		limits := externalQueueLimits
		if long {
			limits.AttemptMillis = upload.MaxAttemptMillis
		}
		q, err = upload.OpenQueue(dir, node, authority, limits, false)
		must(t, err)
		must(t, q.Close())
		if long {
			limits.AttemptMillis = upload.DefaultAttemptMillis
		} else {
			limits.AttemptMillis = upload.MaxAttemptMillis
		}
		if other, err := upload.OpenQueue(dir, node, authority, limits, false); !errors.Is(err, upload.ErrConflict) {
			if other != nil {
				other.Close()
			}
			t.Fatal("retained queue acquired a different ceiling", err)
		}
		after, err := os.ReadFile(filepath.Join(dir, "queue.json"))
		must(t, err)
		if !bytes.Equal(before, after) {
			t.Fatal("inspection modified retained queue")
		}
		wrong := authority
		wrong.Planner, _ = key(t)
		if other, err := openExternalQueue(nil, dir, node, wrong, false, window, nil); err == nil {
			other.Close()
			t.Fatal("ceiling fallback adopted another planner")
		}
	}
	unknown := filepath.Join(f.base, "unknown-queue")
	must(t, os.Mkdir(unknown, 0700))
	limits := externalQueueLimits
	limits.Parallel = 2
	q, err := upload.OpenQueue(unknown, node, authority, limits, true)
	must(t, err)
	must(t, q.Close())
	before, err := os.ReadFile(filepath.Join(unknown, "queue.json"))
	must(t, err)
	if q, err := openExternalQueue(nil, unknown, node, authority, false, upload.MaxAttemptMillis, nil); !errors.Is(err, upload.ErrConflict) {
		if q != nil {
			q.Close()
		}
		t.Fatal("unknown resource identity was adopted", err)
	}
	after, err := os.ReadFile(filepath.Join(unknown, "queue.json"))
	must(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("unknown queue was rewritten")
	}
	must(t, os.WriteFile(filepath.Join(unknown, "queue.json"), []byte("{}"), 0600))
	if q, err := openExternalQueue(nil, unknown, node, authority, false, 0, nil); err == nil {
		q.Close()
		t.Fatal("corrupt queue was recreated")
	}
	for _, window := range []int64{-1, 1, upload.MaxAttemptMillis + 1} {
		if q, err := openExternalQueue(nil, unknown, node, authority, false, window, nil); err == nil {
			q.Close()
			t.Fatal("invalid operation window reached queue", window)
		}
	}
	missing := filepath.Join(f.base, "missing-queue")
	must(t, os.Mkdir(missing, 0700))
	if q, err := openExternalQueue(nil, missing, node, authority, false, upload.MaxAttemptMillis, nil); err == nil {
		q.Close()
		t.Fatal("absent state was initialized by readback")
	}
	entries, err := os.ReadDir(missing)
	must(t, err)
	if len(entries) != 0 {
		t.Fatal("read-only open created files")
	}
}
