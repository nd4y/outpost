package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistentLogsRedactSecretsAndSurviveReopen(t *testing.T) {
	dir := t.TempDir()
	store, err := openLogStore(dir, []string{"test-key", "test-password", "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	writer := store.writer("netbird")
	_, _ = writer.Write([]byte("prefix test-k"))
	_, _ = writer.Write([]byte("ey test-password test-token\n"))
	writer.Write([]byte("unterminated"))
	writer.Flush()
	store.close()
	store, err = openLogStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	store.append("outpost", "restarted")
	store.close()
	data, err := os.ReadFile(filepath.Join(dir, "outpost.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"test-key", "test-password", "test-token"} {
		if strings.Contains(string(data), secret) {
			t.Fatal("secret persisted")
		}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatal("restart lost a log record")
	}
	for _, line := range lines {
		var record map[string]string
		if json.Unmarshal([]byte(line), &record) != nil || record["time"] == "" {
			t.Fatal("invalid structured log")
		}
	}
	info, _ := os.Stat(filepath.Join(dir, "outpost.jsonl"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe log permissions")
	}
}
func TestMetricsCheckpointPreservesAllCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "counters.json")
	m := newMetrics(false)
	m.receivedFiles.Store(12)
	m.sentFiles.Store(7)
	m.receivedBytes.Store(456)
	m.sentBytes.Store(123)
	m.lastTransfer.Store(100)
	if err := m.saveCounters(path); err != nil {
		t.Fatal(err)
	}
	restored := newMetrics(false)
	if err := restored.loadCounters(path); err != nil {
		t.Fatal(err)
	}
	if restored.receivedFiles.Load() != 12 || restored.sentFiles.Load() != 7 || restored.receivedBytes.Load() != 456 || restored.sentBytes.Load() != 123 || restored.lastTransfer.Load() != 100 {
		t.Fatal("restart lost metrics counters")
	}
}
func TestTelemetryEndpointsAndResourceLimits(t *testing.T) {
	c := telemetryConfig{MetricsURL: "http://metrics.example/api/v1/write", LogsURL: "http://logs.example/insert/native"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.Transport = "direct"
	if c.validate() == nil {
		t.Fatal("direct cleartext accepted")
	}
	c.Transport = "netbird"
	c.MetricsURL = "https://user:password@metrics.example/write"
	if c.validate() == nil {
		t.Fatal("credentials in URL accepted")
	}
	c.MetricsURL = "https://metrics.example/write"
	c.Buffer = "0"
	if c.validate() == nil {
		t.Fatal("unbounded buffer accepted")
	}
	c.Buffer = "1GiB"
	c.LogsURL = ""
	if c.validate() == nil {
		t.Fatal("partial push configuration accepted")
	}
}

func TestTelemetryProxyIsExplicitAndBoundToLoopback(t *testing.T) {
	t.Setenv("NB_MANAGEMENT_URL", "https://management.example")
	t.Setenv("NB_SETUP_KEY", "00000000-0000-0000-0000-000000000000")
	t.Setenv("NB_HOSTNAME", "outpost-test")
	t.Setenv("OUTPOST_METRICS_URL", "https://metrics.example/api/v1/write")
	t.Setenv("OUTPOST_LOGS_URL", "https://logs.example/insert/native")
	t.Setenv("OUTPOST_TELEMETRY_TRANSPORT", "netbird")
	t.Setenv("NB_SOCKS5_LISTENER_ADDRESS", "0.0.0.0")
	env, err := netbirdEnv()
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, item := range env {
		fields := strings.SplitN(item, "=", 2)
		values[fields[0]] = fields[1]
	}
	if values["NB_NETSTACK_SKIP_PROXY"] != "false" || values["NB_SOCKS5_LISTENER_ADDRESS"] != "127.0.0.1" || values["NB_SOCKS5_LISTENER_PORT"] != "1080" {
		t.Fatal("unsafe overlay proxy configuration")
	}
	t.Setenv("OUTPOST_TELEMETRY_TRANSPORT", "direct")
	env, err = netbirdEnv()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range env {
		if item == "NB_NETSTACK_SKIP_PROXY=false" {
			t.Fatal("proxy enabled for direct transport")
		}
	}
}
