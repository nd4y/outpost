package upload

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSlotRotationKeepsCompletedPartsAndRequeuesOnlyLostPart(t *testing.T) {
	for _, lose := range []bool{false, true} {
		name := "rotation"
		if lose {
			name = "lost-part"
		}
		t.Run(name, func(t *testing.T) {
			f := fixtureBytes(t, 512<<10)
			target := f.server(t, "webdav", 100*time.Millisecond, nil)
			var mu sync.Mutex
			first := ""
			removed := false
			var removeErr error
			if lose {
				target.Options.AfterWrite = func(w http.ResponseWriter, r *http.Request, actor, key string, body []byte) bool {
					if !strings.HasPrefix(key, "part-") {
						return false
					}
					mu.Lock()
					defer mu.Unlock()
					if first == "" {
						first = key
					} else if key != first && !removed {
						removed = true
						removeErr = os.Remove(filepath.Join(target.Options.Directory, target.Options.Namespace+"-"+first))
					}
					return false
				}
			}
			raw := f.plan(t, target, 1, 500)
			dir := filepath.Join(f.base, "rotation-journal")
			must(t, os.Mkdir(dir, 0700))
			j, e := Open(dir, raw, f.workers[0].ID, f.authority, true)
			must(t, e)
			defer j.Close()
			backend := f.backend(t, target, 0)
			defer backend.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			_, e = j.Run(ctx, f.replicas[0], backend, f.keys[0])
			must(t, e)
			state, e := j.Status(ctx)
			must(t, e)
			minRound, maxRound := int64(1<<62), int64(0)
			for _, p := range state.Parts {
				if !p.Complete {
					t.Fatal("part incomplete after publication")
				}
				minRound = min(minRound, p.Round)
				maxRound = max(maxRound, p.Round)
			}
			if maxRound == minRound {
				t.Fatal("slot rotation was not exercised")
			}
			mu.Lock()
			wasRemoved, err, key := removed, removeErr, first
			mu.Unlock()
			if lose && (!wasRemoved || err != nil || target.Snapshot().Writes[key] != 2) {
				t.Fatal("lost part was not independently repaired", wasRemoved, err, target.Snapshot().Writes[key])
			}
			recoverBytes(t, f, target, f.id, f.version, f.data)
		})
	}
}
