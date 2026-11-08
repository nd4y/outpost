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

	"github.com/nd4y/outpost/internal/control"
)

func TestSourceAgentSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_SOURCE_KILL_INPUT")
	if file == "" {
		t.Skip("child only")
	}
	var input struct {
		Bootstrap  Bootstrap
		Point      string
		Schedule   bool
		Settlement *control.SettlementAdmission
		Retirement []byte
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
	if input.Settlement != nil {
		must(t, a.Settle(ctx, *input.Settlement))
	} else if len(input.Retirement) != 0 {
		must(t, a.RetireUnstarted(ctx, input.Retirement))
	} else if input.Schedule {
		must(t, a.RunSchedule(ctx))
	} else {
		must(t, a.Next(ctx))
		must(t, a.Run(ctx))
	}
	t.Fatal("kill point not reached")
}

func TestSourceAgentSIGKILLFencesAndFinalHead(t *testing.T) {
	for _, point := range []string{"source-agent-intent-durable", "source-agent-before-head", "source-schedule-head-observed"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			scheduled := point == "source-schedule-head-observed"
			if scheduled {
				must(t, f.a.ConfigureSchedule(context.Background(), testSchedule()))
			}
			must(t, f.a.Close())
			f.a = nil
			input := struct {
				Bootstrap Bootstrap
				Point     string
				Schedule  bool
			}{f.b, point, scheduled}
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
			if scheduled {
				must(t, f.a.scheduleStep(context.Background()))
				s, e := f.a.ScheduleStatus(context.Background())
				must(t, e)
				if s.LastSequence != 1 || s.Attempts != 1 || s.Phase != "READY" {
					t.Fatal("schedule lost accepted head", s)
				}
			} else {
				must(t, f.a.Next(context.Background()))
				must(t, f.a.Run(context.Background()))
			}
			s, e := f.a.Status(context.Background())
			must(t, e)
			if s.Phase != "COMPLETE" || s.Sequence != 1 {
				t.Fatal("crash created or lost generation", s)
			}
		})
	}
}
