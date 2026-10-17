package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type metrics struct {
	started         time.Time
	netbirdRequired bool
	receiverReady   atomic.Bool
	netbirdReady    atomic.Bool
	receivedFiles   atomic.Uint64
	sentFiles       atomic.Uint64
	receivedBytes   atomic.Uint64
	sentBytes       atomic.Uint64
	lastTransfer    atomic.Int64
	mu              sync.Mutex
	pending         string
}

func newMetrics(required bool) *metrics {
	return &metrics{started: time.Now(), netbirdRequired: required}
}

// Daemon transfer logs omit filenames. Only completed recv/send records are counted.
func (m *metrics) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending += string(p)
	for {
		end := strings.IndexByte(m.pending, '\n')
		if end < 0 {
			break
		}
		line := m.pending[:end]
		m.pending = m.pending[end+1:]
		marker := strings.Index(line, "OUTPOST_TRANSFER ")
		if marker < 0 {
			continue
		}
		fields := strings.Fields(line[marker:])
		if len(fields) != 4 {
			continue
		}
		bytes, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			continue
		}
		if _, err = strconv.ParseUint(fields[3], 10, 64); err != nil {
			continue
		}
		switch fields[1] {
		case "recv":
			m.receivedFiles.Add(1)
			m.receivedBytes.Add(bytes)
		case "send":
			m.sentFiles.Add(1)
			m.sentBytes.Add(bytes)
		default:
			continue
		}
		m.lastTransfer.Store(time.Now().Unix())
	}
	if len(m.pending) > 8192 {
		m.pending = ""
	}
	return len(p), nil
}

func (m *metrics) monitor(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+rsyncPort, time.Second)
			m.receiverReady.Store(err == nil)
			if c != nil {
				_ = c.Close()
			}
			if m.netbirdRequired {
				env, err := netbirdEnv()
				probe, cancel := context.WithTimeout(ctx, 4*time.Second)
				if err == nil {
					err = nbCommand(probe, env, "status", "--check", "ready")
				}
				cancel()
				m.netbirdReady.Store(err == nil)
			}
		}
	}
}

func boolMetric(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (m *metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	gauge := func(name, help string, value any) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n%s %v\n", name, help, name, name, value)
	}
	gauge("outpost_up", "Receiver and required NetBird connection are ready; cached for up to 10 seconds.", boolMetric(m.receiverReady.Load() && (!m.netbirdRequired || m.netbirdReady.Load())))
	gauge("outpost_rsync_up", "Local rsync listener is available.", boolMetric(m.receiverReady.Load()))
	gauge("outpost_netbird_required", "NetBird is enabled for this process.", boolMetric(m.netbirdRequired))
	gauge("outpost_netbird_up", "NetBird readiness check succeeded.", boolMetric(m.netbirdReady.Load()))
	gauge("outpost_start_time_seconds", "Unix time of process start.", m.started.Unix())
	gauge("outpost_uptime_seconds", "Seconds since process start.", time.Since(m.started).Seconds())
	gauge("outpost_rsync_last_transfer_timestamp_seconds", "Last completed file transfer; zero before the first transfer.", m.lastTransfer.Load())
	fmt.Fprintf(w, "# HELP outpost_rsync_transferred_files_total Completed file transfers since process start.\n# TYPE outpost_rsync_transferred_files_total counter\noutpost_rsync_transferred_files_total{direction=\"receive\"} %d\noutpost_rsync_transferred_files_total{direction=\"send\"} %d\n", m.receivedFiles.Load(), m.sentFiles.Load())
	fmt.Fprintf(w, "# HELP outpost_rsync_transferred_bytes_total Rsync transfer bytes from completed file records since process start.\n# TYPE outpost_rsync_transferred_bytes_total counter\noutpost_rsync_transferred_bytes_total{direction=\"receive\"} %d\noutpost_rsync_transferred_bytes_total{direction=\"send\"} %d\n", m.receivedBytes.Load(), m.sentBytes.Load())
	var disk syscall.Statfs_t
	err := syscall.Statfs("/data", &disk)
	gauge("outpost_storage_statfs_success", "Filesystem capacity probe succeeded.", boolMetric(err == nil))
	if err == nil {
		gauge("outpost_storage_filesystem_size_bytes", "Backing filesystem size; not the backup directory quota.", uint64(disk.Blocks)*uint64(disk.Bsize))
		gauge("outpost_storage_filesystem_available_bytes", "Backing filesystem bytes available to the process; may not reflect a directory quota.", uint64(disk.Bavail)*uint64(disk.Bsize))
	}
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	gauge("outpost_go_heap_alloc_bytes", "Go supervisor heap bytes; excludes child processes and filesystem cache.", mem.HeapAlloc)
	gauge("outpost_go_goroutines", "Go supervisor goroutines.", runtime.NumGoroutine())
}

func startMetrics(m *metrics) (*http.Server, <-chan error, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{Handler: m, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	return server, done, nil
}
