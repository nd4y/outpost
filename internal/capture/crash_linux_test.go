package capture

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type crashInput struct {
	Profile           Profile
	Authority, Intent []byte
	Owner             ed25519.PublicKey
	Data              filekit.Owner
	Writer            ed25519.PrivateKey
	Trust             generation.Trust
}

func reopenCrashRuntime(t *testing.T, base string, input crashInput) (*Job, *sink, *filekit.Store, *generation.Replica) {
	t.Helper()
	ctx := context.Background()
	r, e := generation.Open(filepath.Join(base, "replica"), input.Trust, false)
	must(t, e)
	session, e := ingress.OpenSession(ctx, ingress.SessionOptions{Directory: filepath.Join(base, "ingress"), Authority: input.Authority, Intent: input.Intent, Owner: input.Owner, Replica: r, Initialize: false})
	must(t, e)
	var intent ingress.Intent
	must(t, json.Unmarshal(input.Intent, &intent))
	p := &provider{path: filepath.Join(base, "source"), view: input.Profile.View, operation: intent.Operation, checkpoint: filepath.Join(base, "job/state/checkpoint.json"), trust: input.Trust}
	if _, e = os.Stat(p.path); os.IsNotExist(e) {
		p.released = true
	}
	remote := &sink{Session: session, provider: p}
	cache, e := filekit.OpenStreamingStore(filepath.Join(base, "cache"), input.Data, false, remote)
	must(t, e)
	job, e := Open(ctx, Options{Directory: filepath.Join(base, "job"), Initialize: false, Profile: input.Profile, Authority: input.Authority, Intent: input.Intent, Owner: input.Owner, Data: input.Data, Writer: input.Writer, Provider: p, Sink: remote, Cache: cache})
	must(t, e)
	return job, remote, cache, r
}
func TestSourceJobCrashChild(t *testing.T) {
	point := os.Getenv("OUTPOST_SOURCE_CRASH")
	if point == "" {
		return
	}
	base := os.Getenv("OUTPOST_SOURCE_CRASH_ROOT")
	raw, e := os.ReadFile(filepath.Join(base, "crash-input.json"))
	must(t, e)
	var input crashInput
	must(t, json.Unmarshal(raw, &input))
	job, remote, cache, r := reopenCrashRuntime(t, base, input)
	defer job.Close()
	defer remote.Close()
	defer cache.Close()
	defer r.Close()
	job.Fault = func(name string) error {
		if name == point {
			return syscall.Kill(os.Getpid(), syscall.SIGKILL)
		}
		return nil
	}
	must(t, job.Run(context.Background()))
	t.Fatal("kill boundary was not reached")
}
func TestSourceJobSIGKILLKeepsCheckpointReleaseAndAckOrdering(t *testing.T) {
	for _, point := range []string{"source-file-durable", "source-checkpoint-durable", "source-provider-released", "source-acknowledged"} {
		t.Run(point, func(t *testing.T) {
			f := setup(t, 1)
			input := crashInput{Profile: f.options.Profile, Authority: f.options.Authority, Intent: f.options.Intent, Owner: f.options.Owner, Data: f.owner, Writer: f.options.Writer, Trust: f.replica.Trust()}
			raw, e := json.Marshal(input)
			must(t, e)
			must(t, os.WriteFile(filepath.Join(f.base, "crash-input.json"), raw, 0600))
			must(t, f.job.Close())
			f.job = nil
			must(t, f.options.Cache.Close())
			must(t, f.sink.Close())
			must(t, f.replica.Close())
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSourceJobCrashChild$")
			command.Env = append(os.Environ(), "OUTPOST_SOURCE_CRASH="+point, "OUTPOST_SOURCE_CRASH_ROOT="+f.base)
			output, e := command.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || ctx.Err() != nil {
				t.Fatalf("no real killed child: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong child termination: %v %s", e, output)
			}
			job, remote, cache, r := reopenCrashRuntime(t, f.base, input)
			defer remote.Close()
			defer cache.Close()
			defer r.Close()
			f.job = job
			f.sink = remote
			f.replica = r
			f.provider = remote.provider
			must(t, job.Run(context.Background()))
			f.restore(t)
		})
	}
}
