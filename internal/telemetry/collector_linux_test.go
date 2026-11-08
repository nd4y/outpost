package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// Opt-in interoperability check. The caller supplies a checksum-bound collector
// binary in an isolated no-network test container. No host daemon is contacted.
func TestTelemetryRealCollectorAcceptsBothSignals(t *testing.T) {
	source := os.Getenv("OUTPOST_TELEMETRY_COLLECTOR")
	if source == "" {
		t.Skip("requires an isolated checksum-bound collector")
	}
	expected := os.Getenv("OUTPOST_TELEMETRY_COLLECTOR_SHA256")
	if !filepath.IsAbs(source) || !storage.ID(expected) {
		t.Fatal("collector path/digest required")
	}
	input, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	info, e := input.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 400<<20 {
		t.Fatal("collector file")
	}
	executable, e := os.CreateTemp("/tmp", "outpost-collector-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(executable.Name())
	h := sha256.New()
	_, e = io.Copy(io.MultiWriter(executable, h), io.LimitReader(input, 400<<20+1))
	if e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		t.Fatal("collector checksum mismatch")
	}
	if e = executable.Chmod(0700); e != nil {
		t.Fatal(e)
	}
	executable.Close()
	server, _, cert, roots := tlsFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	serverCert := server.TLS.Certificates[0]
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
		return path
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[0]})
	certFile := write("server.pem", pemCert)
	key, _ := x509.MarshalPKCS8PrivateKey(serverCert.PrivateKey)
	keyFile := write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
	caFile := write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]}))
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := listener.Addr().String()
	listener.Close()
	output := filepath.Join(dir, "observed.json")
	config := fmt.Sprintf("receivers:\n  otlp:\n    protocols:\n      http:\n        endpoint: %s\n        tls:\n          cert_file: %s\n          key_file: %s\n          client_ca_file: %s\n          min_version: '1.3'\nexporters:\n  file:\n    path: %s\n    flush_interval: 100ms\nservice:\n  telemetry:\n    logs:\n      level: error\n    metrics:\n      level: none\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [file]\n    metrics:\n      receivers: [otlp]\n      exporters: [file]\n", address, certFile, keyFile, caFile, output)
	configFile := write("collector.yaml", []byte(config))
	logFile, e := os.Create(filepath.Join(dir, "collector.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logFile.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, executable.Name(), "--config", configFile)
	process.Stdout = logFile
	process.Stderr = logFile
	if e = process.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			process.Process.Kill()
			<-done
		}
	}()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		connection, e := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if e == nil {
			connection.Close()
			ready = true
			break
		}
		select {
		case e := <-done:
			stopped = true
			raw, _ := os.ReadFile(logFile.Name())
			t.Fatalf("collector exited %v: %s", e, raw)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("collector did not bind")
	}
	client, e := NewClient("https://"+address, cert, roots, peer.Identity(cert.Leaf), peer.Identity(serverCert.Leaf))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	record := fixtureRecord()
	record.ObservedUnix -= 600
	value := int64(3)
	target := storage.Hash([]byte("collector-fixture-target"))
	observed := record.ObservedUnix - 60
	record.Metrics = []Metric{
		{Name: "jobs_running", Value: &value},
		{Name: "space_free_bytes"},
		{Name: "external_http_attempt_request_body_bytes", Target: target, Value: &value},
		{Name: "external_http_attempt_response_body_bytes", Target: target},
		{Name: "external_http_attempt_observed_timestamp_seconds", Target: target, Value: &observed},
	}
	messages, e := Encode(peer.Identity(cert.Leaf), storage.Hash([]byte("domain")), record)
	if e != nil {
		t.Fatal(e)
	}
	for _, m := range messages {
		result := client.Send(ctx, m)
		if result.State != "ACCEPTED" || result.Warning {
			t.Fatal(m.Signal, result)
		}
	}
	process.Process.Signal(syscall.SIGTERM)
	if e = <-done; e != nil {
		stopped = true
		t.Fatal(e)
	}
	stopped = true
	raw, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	for _, expected := range []string{
		"resourceMetrics", "resourceLogs", "outpost_jobs_running", "outpost_space_free_bytes_known",
		"outpost_external_http_attempt_request_body_bytes", "outpost_external_http_attempt_response_body_bytes_known",
		"outpost_external_http_attempt_observed_timestamp_seconds", target, strconv.FormatInt(observed, 10),
		"STATE_CHANGED", strconv.FormatInt(record.ObservedUnix*1000000000, 10),
	} {
		if !bytes.Contains(raw, []byte(expected)) {
			t.Fatalf("collector output missing %s", expected)
		}
	}
	if bytes.Contains(raw, []byte(`"outpost_external_http_attempt_response_body_bytes"`)) {
		t.Fatal("collector exported unknown body bytes as a measurement")
	}
	t.Log("COLLECTOR_PASS: mutually authenticated logs and metrics accepted; original timestamp and unknown marker exported")
}
