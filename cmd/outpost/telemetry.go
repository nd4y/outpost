package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type telemetryConfig struct {
	MetricsURL string `json:"metrics_url"`
	LogsURL    string `json:"logs_url"`
	Transport  string `json:"transport"`
	Token      string `json:"token,omitempty"`
	Buffer     string `json:"buffer,omitempty"`
	Interval   string `json:"interval,omitempty"`
}

func (c *telemetryConfig) validate() error {
	if c.Transport == "" {
		c.Transport = "netbird"
	}
	if c.Buffer == "" {
		c.Buffer = "1GiB"
	}
	if c.Interval == "" {
		c.Interval = "30s"
	}
	if c.Transport != "netbird" && c.Transport != "direct" {
		return errors.New("telemetry transport must be netbird or direct")
	}
	if (c.MetricsURL == "") != (c.LogsURL == "") {
		return errors.New("configure both telemetry endpoints")
	}
	for _, address := range []string{c.MetricsURL, c.LogsURL} {
		if address == "" {
			continue
		}
		u, err := url.Parse(address)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(address, "\r\n,%{") || (u.Scheme != "https" && !(c.Transport == "netbird" && u.Scheme == "http")) {
			return errors.New("invalid telemetry endpoint; direct transport requires HTTPS")
		}
	}
	if c.Buffer != "512MiB" && c.Buffer != "1GiB" && c.Buffer != "2GiB" && c.Buffer != "4GiB" {
		return errors.New("telemetry buffer must be 512MiB, 1GiB, 2GiB or 4GiB per signal")
	}
	interval, err := time.ParseDuration(c.Interval)
	if err != nil || interval < time.Second || interval > 5*time.Minute {
		return errors.New("telemetry interval must be between 1s and 5m")
	}
	if len(c.Token) > 4096 || strings.ContainsAny(c.Token, "\r\n\x00") {
		return errors.New("invalid telemetry token")
	}
	return nil
}
func loadTelemetry() (telemetryConfig, error) {
	var c telemetryConfig
	data, err := os.ReadFile("/state/telemetry.json")
	if err == nil {
		if json.Unmarshal(data, &c) != nil {
			return c, errors.New("invalid saved telemetry configuration")
		}
	} else if !os.IsNotExist(err) {
		return c, errors.New("cannot read telemetry configuration")
	}
	for name, target := range map[string]*string{"OUTPOST_METRICS_URL": &c.MetricsURL, "OUTPOST_LOGS_URL": &c.LogsURL, "OUTPOST_TELEMETRY_TRANSPORT": &c.Transport, "OUTPOST_TELEMETRY_BUFFER": &c.Buffer, "OUTPOST_TELEMETRY_INTERVAL": &c.Interval} {
		if value := os.Getenv(name); value != "" {
			*target = value
		}
	}
	token, err := secret("OUTPOST_TELEMETRY_TOKEN")
	if err != nil {
		return c, err
	}
	if token != "" {
		c.Token = token
	}
	return c, c.validate()
}

type logStore struct {
	mu        sync.Mutex
	dir       string
	file      *os.File
	size      int64
	sensitive []string
	failures  atomic.Uint64
}

func openLogStore(dir string, secrets []string) (*logStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create persistent logs")
	}
	f, err := os.OpenFile(filepath.Join(dir, "outpost.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("cannot open persistent logs")
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &logStore{dir: dir, file: f, size: info.Size(), sensitive: secrets}, nil
}
func (s *logStore) close() { s.mu.Lock(); defer s.mu.Unlock(); _ = s.file.Sync(); _ = s.file.Close() }
func (s *logStore) append(component, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, value := range s.sensitive {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	if len(message) > 4096 {
		message = message[:4096] + " [truncated]"
	}
	entry, _ := json.Marshal(map[string]string{"time": time.Now().UTC().Format(time.RFC3339Nano), "component": component, "message": message})
	entry = append(entry, '\n')
	defer func() { _, _ = os.Stderr.Write(entry) }()
	if s.size+int64(len(entry)) > 16*1024*1024 {
		files, _ := filepath.Glob(filepath.Join(s.dir, "outpost-*.jsonl"))
		sort.Strings(files)
		for len(files) >= 3 {
			if err := os.Remove(files[0]); err != nil {
				s.failures.Add(1)
				return
			}
			files = files[1:]
		}
		if s.file == nil {
			s.failures.Add(1)
			return
		}
		if err := s.file.Sync(); err != nil {
			s.failures.Add(1)
			return
		}
		original := filepath.Join(s.dir, "outpost.jsonl")
		rotated := filepath.Join(s.dir, fmt.Sprintf("outpost-%019d.jsonl", time.Now().UnixNano()))
		if err := os.Rename(original, rotated); err != nil {
			s.failures.Add(1)
			return
		}
		next, err := os.OpenFile(original, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			_ = os.Rename(rotated, original)
			s.failures.Add(1)
			return
		}
		_ = s.file.Close()
		s.file = next
		s.size = 0
	}
	if s.file == nil {
		s.failures.Add(1)
		return
	}
	n, err := s.file.Write(entry)
	s.size += int64(n)
	if err != nil {
		s.failures.Add(1)
		return
	}
	if err = s.file.Sync(); err != nil {
		s.failures.Add(1)
	}

}

type componentLog struct {
	mu                 sync.Mutex
	store              *logStore
	component, pending string
}

func (s *logStore) writer(component string) *componentLog {
	return &componentLog{store: s, component: component}
}
func (w *componentLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending += string(p)
	for {
		end := strings.IndexByte(w.pending, '\n')
		if end < 0 {
			break
		}
		w.store.append(w.component, w.pending[:end])
		w.pending = w.pending[end+1:]
	}
	if len(w.pending) > 4096 {
		w.store.append(w.component, w.pending)
		w.pending = ""
	}
	return len(p), nil
}

func (w *componentLog) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.pending != "" {
		w.store.append(w.component, w.pending)
		w.pending = ""
	}
}

type transferLog struct {
	counter io.Writer
	output  *componentLog
}

func (w *transferLog) Write(p []byte) (int, error) {
	if _, err := w.counter.Write(p); err != nil {
		return 0, err
	}
	return w.output.Write(p)
}
func (w *transferLog) Flush() { w.output.Flush() }

type telemetryAgents struct {
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func startTelemetry(c telemetryConfig, store *logStore) (*telemetryAgents, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &telemetryAgents{cancel: cancel}
	if c.MetricsURL == "" {
		log.Print("push telemetry is not configured; logs remain in the state volume")
		return a, nil
	}
	instance := os.Getenv("NB_HOSTNAME")
	if instance == "" {
		instance = "outpost"
	}
	if !userPattern.MatchString(instance) && !validPeerName(instance) {
		cancel()
		return nil, errors.New("invalid telemetry instance")
	}
	for _, dir := range []string{"/state/vmagent", "/state/vlagent"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			cancel()
			return nil, errors.New("cannot create telemetry state")
		}
	}
	if err := os.WriteFile("/run/outpost/telemetry-token", []byte(c.Token), 0600); err != nil {
		cancel()
		return nil, err
	}
	targets := []any{}
	for _, item := range []struct{ name, socket string }{{"outpost", "metrics"}, {"outpost-vmagent", "vmagent"}, {"outpost-vlagent", "vlagent"}} {
		targets = append(targets, map[string]any{"job_name": item.name, "scrape_interval": c.Interval, "scrape_timeout": "1s", "static_configs": []any{map[string]any{"targets": []string{"outpost:80"}, "labels": map[string]string{"__unix_socket__": "/run/outpost/" + item.socket + ".sock", "instance": instance}}}})
	}
	config, _ := json.Marshal(map[string]any{"scrape_configs": targets})
	if err := os.WriteFile("/run/outpost/vmagent.json", config, 0600); err != nil {
		cancel()
		return nil, err
	}
	common := []string{"-memory.allowedBytes=64MiB", "-loggerLevel=WARN", "-remoteWrite.maxDiskUsagePerURL=" + c.Buffer, "-remoteWrite.queues=1", "-remoteWrite.flushInterval=1s", "-remoteWrite.sendTimeout=5s", "-remoteWrite.bearerTokenFile=/run/outpost/telemetry-token"}
	if c.Transport == "netbird" {
		common = append(common, "-remoteWrite.proxyURL=socks5://127.0.0.1:1080")
	}
	metricsArgs := append(append([]string{}, common...), "-httpListenAddr=unix:/run/outpost/vmagent.sock", "-promscrape.config=/run/outpost/vmagent.json", "-remoteWrite.tmpDataPath=/state/vmagent", "-remoteWrite.url="+c.MetricsURL, "-remoteWrite.forcePromProto=true")
	fields, _ := json.Marshal(map[string]string{"job": "outpost", "instance": instance})
	logsArgs := append(append([]string{}, common...), "-httpListenAddr=unix:/run/outpost/vlagent.sock", "-tmpDataPath=/state/vlagent", "-remoteWrite.tmpDataPath=/state/vlagent/queue", "-remoteWrite.url="+c.LogsURL, "-fileCollector.glob=/state/logs/outpost*.jsonl", "-fileCollector.checkpointsPath=/state/vlagent/checkpoints.json", "-fileCollector.fileField=", "-fileCollector.hostnameField=", "-fileCollector.streamFields='job,instance,component'", "-fileCollector.extraFields="+string(fields))
	a.supervise(ctx, "vmagent", metricsArgs, store)
	a.supervise(ctx, "vlagent", logsArgs, store)
	return a, nil
}
func validPeerName(name string) bool {
	return len(name) <= 63 && strings.Trim(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-") == ""
}
func (a *telemetryAgents) supervise(ctx context.Context, name string, args []string, store *logStore) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for ctx.Err() == nil {
			cmd, done, err := child("/usr/bin/"+name, args, []string{"PATH=/usr/bin", "HOME=/state", "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt", "GOMAXPROCS=2"}, store.writer(name))
			if err == nil {
				select {
				case <-done:
				case <-ctx.Done():
					stop(cmd)
					select {
					case <-done:
					case <-time.After(15 * time.Second):
						if cmd.Process != nil {
							_ = cmd.Process.Kill()
						}
					}
				}
			}
			if ctx.Err() != nil {
				return
			}
			store.append("outpost", name+" exited; restarting the telemetry sender")
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
}
func (a *telemetryAgents) close() { a.cancel(); a.wg.Wait() }

// Preserve counters for container recreation as well as restart.
func (m *metrics) saveCounters(path string) error {
	data, err := json.Marshal([]uint64{m.receivedFiles.Load(), m.sentFiles.Load(), m.receivedBytes.Load(), m.sentBytes.Load(), uint64(m.lastTransfer.Load())})
	if err != nil {
		return err
	}
	return atomicState(path, data)
}
func (m *metrics) loadCounters(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var values []uint64
	if json.Unmarshal(data, &values) != nil || len(values) != 5 {
		return errors.New("invalid saved metrics counters")
	}
	m.receivedFiles.Store(values[0])
	m.sentFiles.Store(values[1])
	m.receivedBytes.Store(values[2])
	m.sentBytes.Store(values[3])
	m.lastTransfer.Store(int64(values[4]))
	return nil
}
func atomicState(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".outpost-state-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
