package generation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type crashInput struct {
	Trust   Trust
	Raw     []byte
	Objects map[string][]byte
	ID      string
	Permit  []byte
}

func TestReplicaCrashChild(t *testing.T) {
	if os.Getenv("OUTPOST_G2_CHILD") != "1" {
		return
	}
	base := os.Getenv("OUTPOST_G2_ROOT")
	b, e := os.ReadFile(filepath.Join(base, "child.json"))
	ok(t, e)
	var input crashInput
	ok(t, json.Unmarshal(b, &input))
	r, e := Open(filepath.Join(base, "replica"), input.Trust, false)
	ok(t, e)
	defer r.Close()
	point := os.Getenv("OUTPOST_G2_POINT")
	r.Fault = func(name string) error {
		if name == point {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	switch os.Getenv("OUTPOST_G2_ACTION") {
	case "receive":
		_, e = r.Receive(ctx, input.Raw, fetch(input.Objects))
	case "complete":
		e = r.Complete(ctx, input.ID)
	case "maintain":
		_, e = r.Maintain(ctx, input.Permit)
	default:
		t.Fatal("unknown child action")
	}
	t.Fatalf("SIGKILL boundary not reached: %v", e)
}

func TestReplicaSIGKILLBoundaries(t *testing.T) {
	for _, tc := range []struct{ action, point string }{{"receive", "object-durable"}, {"receive", "before-complete"}, {"complete", "state-durable"}, {"maintain", "retirement-authority-durable"}, {"maintain", "retirement-durable"}, {"maintain", "gc-object-removed"}} {
		t.Run(tc.action+"/"+tc.point, func(t *testing.T) {
			base := temp(t)
			trust, key, maintenance := trust(t)
			r := openTest(t, filepath.Join(base, "replica"), trust)
			a, objects := synthetic(t, trust, key, 1, "old")
			old, e := r.Receive(ctx, a, fetch(objects))
			ok(t, e)
			b, newObjects := synthetic(t, trust, key, 2, "new")
			id := Hash(b)
			input := crashInput{Trust: trust, Raw: b, Objects: newObjects, ID: id}
			if tc.action != "receive" {
				_, e = r.Begin(ctx, b)
				ok(t, e)
				for key, data := range newObjects {
					ok(t, r.Put(ctx, id, key, data))
				}
			}
			if tc.action == "maintain" {
				ok(t, r.Complete(ctx, id))
				input.Permit = permit(t, r, maintenance, old)
			}
			data, e := json.Marshal(input)
			ok(t, e)
			ok(t, os.WriteFile(filepath.Join(base, "child.json"), data, 0600))
			ok(t, r.Close())
			bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestReplicaCrashChild$", "-test.timeout=15s")
			cmd.Env = append(os.Environ(), "OUTPOST_G2_CHILD=1", "OUTPOST_G2_ROOT="+base, "OUTPOST_G2_POINT="+tc.point, "OUTPOST_G2_ACTION="+tc.action)
			log, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				t.Fatalf("child was not killed: %v %s", e, log)
			}
			status, yes := exit.Sys().(syscall.WaitStatus)
			if !yes || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("not actual SIGKILL: %v %s", e, log)
			}
			r, e = Open(filepath.Join(base, "replica"), trust, false)
			ok(t, e)
			defer r.Close()
			state, e := r.Status(ctx)
			ok(t, e)
			if tc.action == "receive" {
				if state.LatestComplete != old {
					t.Fatal("interrupted reception replaced complete root")
				}
				_, e = r.Receive(ctx, b, fetch(newObjects))
				ok(t, e)
			} else if state.LatestComplete != id {
				t.Fatal("durable complete root lost")
			}
			if tc.action == "maintain" {
				_, e = r.Maintain(ctx, input.Permit)
				ok(t, e)
				if _, e = r.BeginHistorical(ctx, a); !errors.Is(e, ErrProtected) {
					t.Fatal("retirement authority lost across SIGKILL", e)
				}
			}
			c, refs, e := getForTest(r, id)
			ok(t, e)
			if c.Sequence != 2 {
				t.Fatal("wrong complete root")
			}
			for _, ref := range refs {
				_, e = r.ReadObject(ctx, id, ref)
				ok(t, e)
			}
			t.Log("SIGKILL confirmed; latest complete closure verified after reopen and retry")
		})
	}
}
func getForTest(r *Replica, id string) (Catalog, map[string]Object, error) {
	b, e := r.Catalog(ctx, id)
	if e != nil {
		return Catalog{}, nil, e
	}
	c, e := VerifyCatalog(b, r.trust)
	if e != nil {
		return c, nil, e
	}
	refs, e := closure(c)
	return c, refs, e
}
