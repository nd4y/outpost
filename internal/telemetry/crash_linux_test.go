package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTelemetryCrashChild(t *testing.T) {
	dir := os.Getenv("OUTPOST_TELEMETRY_CRASH_DIR")
	if dir == "" {
		t.Skip("subprocess only")
	}
	phase := os.Getenv("OUTPOST_TELEMETRY_CRASH_PHASE")
	q, e := Open(fixtureOptions(filepath.Join(dir, "queue")))
	if e != nil {
		t.Fatal(e)
	}
	defer q.Close()
	q.Fault = func(point string) error {
		if point == phase {
			fmt.Println("TELEMETRY_CRASH_READY")
			select {}
		}
		return nil
	}
	if e = q.Enqueue(context.Background(), 1, fixtureRecord()); e != nil {
		t.Fatal(e)
	}
	_, e = q.Deliver(context.Background(), sendFunc(func(_ context.Context, m Message) Outcome {
		f, e := os.OpenFile(filepath.Join(dir, "remote-accepted"), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(m.Body); e != nil {
			t.Fatal(e)
		}
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		f.Close()
		return Outcome{State: "ACCEPTED"}
	}))
	if e != nil {
		t.Fatal(e)
	}
}
func TestTelemetrySIGKILLPreservesCursorAndUnknownAck(t *testing.T) {
	for _, phase := range []string{"enqueued", "before-send", "after-send", "settled"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTelemetryCrashChild$")
			child.Env = append(os.Environ(), "OUTPOST_TELEMETRY_CRASH_DIR="+dir, "OUTPOST_TELEMETRY_CRASH_PHASE="+phase)
			pipe, e := child.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr bytes.Buffer
			child.Stderr = &stderr
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			scanner := bufio.NewScanner(pipe)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "TELEMETRY_CRASH_READY" {
					ready = true
					break
				}
			}
			child.Process.Kill()
			child.Wait()
			if !ready {
				t.Fatal("child did not reach boundary", stderr.String())
			}
			o := fixtureOptions(filepath.Join(dir, "queue"))
			o.Initialize = false
			q := fixtureOpen(t, o)
			s, e := q.Status(context.Background())
			if e != nil || s.Cursor != 1 {
				t.Fatal(s, e)
			}
			if phase == "settled" {
				if s.Pending != 0 || s.Accepted != 1 {
					t.Fatal(s)
				}
				return
			}
			if s.Pending != 1 || s.Accepted != 0 {
				t.Fatal(s)
			}
			due(t, q)
			previous, _ := os.ReadFile(filepath.Join(dir, "remote-accepted"))
			s, e = q.Deliver(context.Background(), sendFunc(func(_ context.Context, m Message) Outcome {
				if phase == "after-send" && !bytes.Equal(previous, m.Body) {
					t.Fatal("uncertain request changed after SIGKILL")
				}
				return Outcome{State: "ACCEPTED"}
			}))
			if e != nil || s.Pending != 0 || s.Accepted != 1 {
				t.Fatal(s, e)
			}
		})
	}
}
