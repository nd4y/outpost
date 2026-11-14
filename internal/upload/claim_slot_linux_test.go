package upload

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A long operation does not grant a longer signed network slot. The control
// changes only the owner-selected slot before signing, never a live lease.
func TestSlowClaimRespectsSlotEvenWithLongerOperation(t *testing.T) {
	for _, slot := range []int64{500, 4000} {
		name := "short-slot-refused"
		if slot == 4000 {
			name = "admitted-slower-profile"
		}
		t.Run(name, func(t *testing.T) {
			f := fixtureBytes(t, 4096)
			var claims, payloads atomic.Int64
			target := f.server(t, "webdav", 0, func(_ http.ResponseWriter, r *http.Request, _, key string, _ []byte) bool {
				if r.Method == http.MethodPut && strings.HasPrefix(key, "part-") {
					payloads.Add(1)
				}
				if r.Method != http.MethodPut || !strings.HasPrefix(key, "claim-") {
					return false
				}
				claims.Add(1)
				select {
				case <-time.After(1200 * time.Millisecond):
					return false
				case <-r.Context().Done():
					return true
				}
			})
			raw := f.plan(t, target, 1, slot)
			dir := filepath.Join(f.base, "claim-slot")
			must(t, os.Mkdir(dir, 0700))
			j, err := Open(dir, raw, f.workers[0].ID, f.authority, true)
			must(t, err)
			defer j.Close()
			backend := f.backend(t, target, 0)
			defer backend.Close()
			budget := 6 * time.Second
			if slot == 4000 {
				budget = 12 * time.Second
			}
			ctx, stop := context.WithTimeout(t.Context(), budget)
			defer stop()
			_, runError := j.Run(ctx, f.replicas[0], backend, f.keys[0])
			state, err := j.Status(t.Context())
			must(t, err)
			t.Logf("claim profile slot=%dms delay=1200ms attempts=%d payloadPUTs=%d phase=%s", slot, claims.Load(), payloads.Load(), state.Phase)
			if claims.Load() == 0 {
				t.Fatal("control never attempted a claim")
			}
			if slot == 500 {
				if !errors.Is(runError, context.DeadlineExceeded) || payloads.Load() != 0 || state.Phase == "COMPLETE" || state.Receipt != nil {
					t.Fatal("operation budget bypassed the original claim-slot fence", runError)
				}
				pins, err := f.replicas[0].Status(t.Context())
				must(t, err)
				if _, ok := pins.Pins[workerPin(j.planID, j.worker)]; !ok {
					t.Fatal("incomplete slot profile lost source protection")
				}
			} else {
				must(t, runError)
				if payloads.Load() == 0 || state.Phase != "COMPLETE" || state.Receipt == nil {
					t.Fatal("owner-admitted slot profile did not complete")
				}
				recoverBytes(t, f, target, f.id, f.version, f.data)
			}
		})
	}
}
