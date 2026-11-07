package sourceagent

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSourceAgentSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_SOURCE_KILL_INPUT")
	if file == "" {
		t.Skip("child only")
	}
	var input struct {
		Bootstrap Bootstrap
		Point     string
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	must(t, json.Unmarshal(raw, &input))
	ctx := context.Background()
	a, e := Open(ctx, input.Bootstrap, false)
	must(t, e)
	defer a.Close()
	a.Fault = func(p string) error {
		if p == input.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	must(t, a.Next(ctx))
	must(t, a.Run(ctx))
	t.Fatal("kill point not reached")
}

func TestSourceAgentSIGKILLFencesAndFinalHead(t *testing.T) {
	for _, point := range []string{"source-agent-intent-durable", "source-agent-before-head"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			must(t, f.a.Close())
			f.a = nil
			input := struct {
				Bootstrap Bootstrap
				Point     string
			}{f.b, point}
			raw, e := json.Marshal(input)
			must(t, e)
			file := filepath.Join(f.base, "child-input.json")
			must(t, os.WriteFile(file, raw, 0600))
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSourceAgentSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_SOURCE_KILL_INPUT="+file)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || ctx.Err() != nil {
				t.Fatalf("child did not exit by signal: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong termination: %v %s", e, output)
			}
			f.a, e = Open(context.Background(), f.b, false)
			must(t, e)
			must(t, f.a.Next(context.Background()))
			must(t, f.a.Run(context.Background()))
			s, e := f.a.Status(context.Background())
			must(t, e)
			if s.Phase != "COMPLETE" || s.Sequence != 1 {
				t.Fatal("crash created or lost generation", s)
			}
		})
	}
}
