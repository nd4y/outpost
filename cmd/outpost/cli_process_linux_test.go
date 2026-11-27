package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	cliFlowLogMaxBytes int64 = 1 << 20
	cliFlowTermGrace         = 10 * time.Second
	cliFlowKillGrace         = 5 * time.Second
)

// cliFlowStatus is a point-in-time view of a started CLI child. It never
// consumes the single Wait result.
type cliFlowStatus struct {
	Running bool
	Exited  bool
	Err     error
}

// cliFlowProcess owns exactly one structured CLI child started by a test. All
// methods are safe to call concurrently; only the start goroutine calls Wait.
type cliFlowProcess struct {
	name string
	cmd  *exec.Cmd
	done chan struct{}

	stopMu  sync.Mutex
	mu      sync.Mutex
	exited  bool
	waitErr error
	stopped bool
}

// startCLIFlowProcess starts the selected CLI binary directly (no shell) with
// bounded, private stdout/stderr logs in t.TempDir. The returned process is
// always registered for cleanup so this test cannot leave its own child behind.
func startCLIFlowProcess(t *testing.T, binary, logParent string, args ...string) *cliFlowProcess {
	t.Helper()
	if binary == "" {
		t.Fatal("cli flow: executable is required")
	}
	if !filepath.IsAbs(logParent) {
		t.Fatal("cli flow: absolute private log directory required")
	}
	dir, err := os.MkdirTemp(logParent, "process-")
	if err != nil {
		t.Fatalf("cli flow: create private log directory: %v", err)
	}
	stdoutPath := filepath.Join(dir, "stdout.log")
	stderrPath := filepath.Join(dir, "stderr.log")
	stdout, err := newCLIFlowLog(stdoutPath)
	if err != nil {
		t.Fatalf("cli flow: create stdout log: %v", err)
	}
	stderr, err := newCLIFlowLog(stderrPath)
	if err != nil {
		_ = stdout.Close()
		t.Fatalf("cli flow: create stderr log: %v", err)
	}
	command := exec.Command(binary, args...) // Structured argv, never a shell.
	command.Stdout = stdout
	command.Stderr = stderr
	p := &cliFlowProcess{
		name: filepath.Base(binary),
		cmd:  command,
		done: make(chan struct{}),
	}
	if err = command.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		t.Fatalf("cli flow: start %s: %v", p.name, err)
	}
	go func() {
		// This is the only Wait call. The result is published before done is
		// closed, so watchers observe either Running or a stable exit result.
		waitErr := command.Wait()
		_ = stdout.Close() // Wait has joined its I/O copiers by now.
		_ = stderr.Close()
		p.mu.Lock()
		p.exited = true
		p.waitErr = waitErr
		p.mu.Unlock()
		close(p.done)
	}()
	t.Cleanup(func() { p.Stop(t) })
	return p
}

// Running reports whether Wait has not yet observed the child's exit. It does
// not consume or replace the sole Wait result.
func (p *cliFlowProcess) Running() bool {
	return p.Status().Running
}

// Status returns a consistent snapshot without touching the Wait channel.
func (p *cliFlowProcess) Status() cliFlowStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cliFlowStatus{Running: !p.exited, Exited: p.exited, Err: p.waitErr}
}

// Stop requests graceful cancellation with SIGTERM, waits up to ten seconds,
// then kills and joins only this child. A clean exit is required. Repeated or
// concurrent calls are serialized and become no-ops after the first Stop.
func (p *cliFlowProcess) Stop(t *testing.T) {
	t.Helper()
	p.stopWithSignal(t, syscall.SIGTERM)
}

func (p *cliFlowProcess) stopWithSignal(t *testing.T, signal syscall.Signal) {
	t.Helper()
	p.stopMu.Lock()
	defer p.stopMu.Unlock()

	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	exited := p.exited
	p.mu.Unlock()
	if exited {
		t.Errorf("cli flow %s: daemon exited before requested stop", p.name)
	}

	if !exited {
		if err := p.cmd.Process.Signal(signal); err != nil {
			t.Errorf("cli flow %s: send %s: %v", p.name, signal, err)
		}
	}

	term := time.NewTimer(cliFlowTermGrace)
	defer term.Stop()
	select {
	case <-p.done:
		p.reportExit(t)
		return
	case <-term.C:
	}
	t.Errorf("cli flow %s: graceful stop exceeded deadline", p.name)

	if err := p.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("cli flow %s: kill after %s timeout: %v", p.name, signal, err)
	}
	kill := time.NewTimer(cliFlowKillGrace)
	defer kill.Stop()
	select {
	case <-p.done:
	case <-kill.C:
		p.mu.Lock()
		p.stopped = true
		p.mu.Unlock()
		t.Errorf("cli flow %s: child did not join after SIGKILL", p.name)
		return
	}
	p.reportExit(t)
}

func (p *cliFlowProcess) reportExit(t *testing.T) {
	t.Helper()
	p.mu.Lock()
	p.stopped = true
	waitErr := p.waitErr
	p.mu.Unlock()
	if waitErr != nil {
		// ExitError describes only the exit status. Log contents are bounded,
		// retained under t.TempDir, and deliberately not printed here.
		t.Errorf("cli flow %s: process did not exit cleanly: %v", p.name, waitErr)
	}
}

// cliFlowLog is a private, size-bounded writer. Once the cap is reached it
// discards further bytes instead of blocking the child or growing memory.
type cliFlowLog struct {
	mu        sync.Mutex
	file      *os.File
	remaining int64
	closed    bool
	truncated bool
}

func newCLIFlowLog(path string) (*cliFlowLog, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	return &cliFlowLog{file: file, remaining: cliFlowLogMaxBytes}, nil
}

func (l *cliFlowLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.file == nil || l.remaining <= 0 {
		l.truncated = l.truncated || len(p) > 0
		return len(p), nil
	}
	limit := int64(len(p))
	if limit > l.remaining {
		limit = l.remaining
		l.truncated = true
	}
	written, err := l.file.Write(p[:limit])
	l.remaining -= int64(written)
	if err != nil {
		return written, err
	}
	if int64(written) != limit {
		return written, io.ErrShortWrite
	}
	return len(p), nil
}

func (l *cliFlowLog) Truncated() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.truncated
}

func (l *cliFlowLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
