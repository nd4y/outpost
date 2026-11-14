package upload

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
			requestKinds := map[string]int{}
			target.Options.Before = func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
				mu.Lock()
				requestKinds[r.Method+"/"+strings.SplitN(key, "-", 2)[0]]++
				mu.Unlock()
				return false
			}
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
			var journalWrites int
			var cancelledAdmissions int
			var journalTime, longestWrite time.Duration
			j.Admit = func(_ string, _ int) (func(bool) error, error) {
				started := time.Now()
				return func(committed bool) error {
					elapsed := time.Since(started)
					mu.Lock()
					if committed {
						journalWrites++
						journalTime += elapsed
						longestWrite = max(longestWrite, elapsed)
					} else {
						cancelledAdmissions++
					}
					mu.Unlock()
					return nil
				}, nil
			}
			backend := f.backend(t, target, 0)
			defer backend.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			started := time.Now()
			_, e = j.Run(ctx, f.replicas[0], backend, f.keys[0])
			t.Logf("slot worker result elapsed=%s error=%v", time.Since(started), e)
			logUploadProfile(t, name+"-after-slot", target, nil)
			if status, err := j.Status(context.Background()); err == nil {
				complete := 0
				for _, part := range status.Parts {
					if part.Complete {
						complete++
					}
				}
				tasks, err := j.plan.Tasks()
				must(t, err)
				t.Logf("slot durable progress completed=%d started=%d planned=%d phase=%s", complete, len(status.Parts), len(tasks), status.Phase)
				for index, task := range tasks {
					part := status.Parts[task.Part.ID]
					t.Logf("slot part index=%d bytes=%d object-bytes=%d attempts=%d complete=%t round=%d", index, task.Part.Bytes, task.Object.Bytes, part.Attempts, part.Complete, part.Round)
				}
			}
			mu.Lock()
			t.Logf("slot journal committed-writes=%d cancelled-admissions=%d elapsed=%s longest=%s requests=%v", journalWrites, cancelledAdmissions, journalTime, longestWrite, requestKinds)
			mu.Unlock()
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

func TestVerifiedPartProgressSurvivesLocalLockAcrossSlot(t *testing.T) {
	f := fixtureBytes(t, 16<<10)
	target := f.server(t, "webdav", 0, nil)
	raw := f.plan(t, target, 1, 3000)
	dir := filepath.Join(f.base, "ack-journal")
	must(t, os.Mkdir(dir, 0700))
	j, err := Open(dir, raw, f.workers[0].ID, f.authority, true)
	must(t, err)
	defer j.Close()
	backend := f.backend(t, target, 0)
	defer backend.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	var once atomic.Bool
	var mu sync.Mutex
	var heldPart string
	var heldAttempt uint64
	var rechecksBeforeLocalACK int
	var hookError error
	claimEnds := map[string]int64{}
	joined := make(chan struct{})
	target.Options.Before = func(w http.ResponseWriter, r *http.Request, _, key string, body []byte) bool {
		if r.Method == http.MethodPut && strings.HasPrefix(key, "claim-") {
			var document struct {
				Object        string `json:"part"`
				ExpiresMillis int64  `json:"expiresMillis"`
				Claims        []struct {
					Object        string `json:"part"`
					ExpiresMillis int64  `json:"expiresMillis"`
				} `json:"claims"`
			}
			if err := json.Unmarshal(body, &document); err != nil {
				mu.Lock()
				hookError = err
				mu.Unlock()
				return false
			}
			mu.Lock()
			if document.Object != "" {
				claimEnds[document.Object] = document.ExpiresMillis
			}
			for _, member := range document.Claims {
				claimEnds[member.Object] = member.ExpiresMillis
			}
			mu.Unlock()
		}
		partID := strings.TrimPrefix(key, "part-")
		mu.Lock()
		expires := claimEnds[partID]
		isHeld := once.Load() && heldPart == partID
		mu.Unlock()
		if r.Method == http.MethodGet && strings.HasPrefix(key, "part-") && isHeld {
			status, err := j.Status(ctx)
			mu.Lock()
			if err != nil {
				hookError = err
			} else if !status.Parts[partID].Complete {
				rechecksBeforeLocalACK++
			}
			mu.Unlock()
		}
		if r.Method != http.MethodGet || !strings.HasPrefix(key, "part-") || target.Snapshot().Writes[key] != 1 || time.Until(time.UnixMilli(expires)) < 200*time.Millisecond || !once.CompareAndSwap(false, true) {
			return false
		}
		unlock, err := lock(ctx, j.root, "state.lock")
		if err != nil {
			mu.Lock()
			hookError = err
			mu.Unlock()
			close(joined)
			http.Error(w, "controlled local lock failure", http.StatusServiceUnavailable)
			return true
		}
		snapshot, err := j.load()
		if err != nil {
			unlock()
			mu.Lock()
			hookError = err
			mu.Unlock()
			close(joined)
			http.Error(w, "controlled journal read failure", http.StatusServiceUnavailable)
			return true
		}
		mu.Lock()
		heldPart, heldAttempt = partID, snapshot.Parts[partID].Attempts
		mu.Unlock()
		end := time.UnixMilli(expires)
		// The cloud's real readback response can finish now, while a separate
		// local writer holds only the journal lock beyond that assignment slot.
		go func() {
			defer close(joined)
			defer unlock()
			timer := time.NewTimer(time.Until(end.Add(250 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
			}
		}()
		return false
	}
	_, runError := j.Run(ctx, f.replicas[0], backend, f.keys[0])
	if once.Load() {
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Fatal("owned journal-lock control did not join")
		}
	}
	must(t, runError)
	mu.Lock()
	part, attempt, rechecks, err := heldPart, heldAttempt, rechecksBeforeLocalACK, hookError
	mu.Unlock()
	must(t, err)
	state, err := j.Status(ctx)
	must(t, err)
	progress := state.Parts[part]
	if part == "" || attempt == 0 {
		t.Fatal("control did not reach a readback with sufficient original lease headroom")
	}
	if !progress.Complete || progress.Attempts != attempt || rechecks != 0 || target.Snapshot().Writes["part-"+part] != 1 {
		t.Fatal("verified immutable part was retried only because its local acknowledgement crossed a slot", progress, "premature-readbacks", rechecks)
	}
	recoverBytes(t, f, target, f.id, f.version, f.data)
}
