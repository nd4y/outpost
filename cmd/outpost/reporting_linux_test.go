package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

func TestCLIReportingOwnerEnrollmentScheduleStatusAndExplicitRenew(t *testing.T) {
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	ctx := context.Background()
	base := teststore.Root(t)
	key := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		p, k, e := ed25519.GenerateKey(rand.Reader)
		must(e)
		return p, k
	}
	owner, ownerKey := key()
	nodeKey, nodePrivate := key()
	writer, _ := key()
	maintenance, _ := key()
	planner, _ := key()
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, nodeKey, nodePrivate)
	must(e)
	cert, e := x509.ParseCertificate(der)
	must(e)
	node := storage.Hash(cert.RawSubjectPublicKeyInfo)
	certFile, keyFile := filepath.Join(base, "tls.pem"), filepath.Join(base, "tls-key.pem")
	must(os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	pk, e := x509.MarshalPKCS8PrivateKey(nodePrivate)
	must(e)
	must(os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600))
	put := func(name string, v any) string {
		raw, e := json.Marshal(v)
		must(e)
		path := filepath.Join(base, name)
		must(os.WriteFile(path, raw, 0600))
		return path
	}
	root := filepath.Join(base, "volume")
	must(os.Mkdir(root, 0700))
	probe, e := volume.Probe(ctx, root)
	must(e)
	binding, e := volume.Enroll(ctx, root, probe, node, 1)
	must(e)
	bootstrap := put("worker.json", worker.Bootstrap{Format: worker.BootstrapFormat, Volume: binding, Directory: filepath.Join(root, "worker"), Node: node, Owner: owner, CertificateFile: certFile, PrivateKeyFile: keyFile, CAFile: certFile, Credentials: map[string]string{}})
	_, e = run(ctx, []string{"worker-init", "--bootstrap", bootstrap})
	must(e)
	domain, repository := storage.Hash([]byte("domain")), storage.Hash([]byte("repository"))
	cfg := control.Config{Format: control.Format, Node: node, Revision: 1, NotBefore: now.Add(-time.Minute).Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 64 << 20, ReserveBytes: 8 << 20, SpoolBytes: 16 << 20, TelemetryBytes: 1 << 20}, Nodes: []policy.Node{{ID: node, Class: "trusted"}}, Domains: []control.Domain{{Trust: generation.Trust{Domain: domain, Repository: repository, Epoch: 1, Writer: writer, Maintenance: maintenance}, Planner: planner, Placement: policy.Placement{Domain: domain, AllowedClasses: []string{"trusted"}, Holders: []string{node}}}}}
	signed, e := control.Sign(cfg, ownerKey)
	must(e)
	configFile := filepath.Join(base, "config.json")
	must(os.WriteFile(configFile, signed, 0600))
	_, e = run(ctx, []string{"config-apply", "--bootstrap", bootstrap, "--input", configFile})
	must(e)
	enrollment := management.Enrollment{Format: management.EnrollmentFormat, Tenant: storage.Hash([]byte("tenant")), Node: node, PublicKey: nodeKey, Class: "trusted", Revision: 1, NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix, Domains: []management.DomainAdmission{{Domain: domain, Repository: repository, Epoch: 1}}}
	ownerFile := put("owner.json", map[string]any{"privateKey": ownerKey})
	input := put("enrollment-input.json", enrollment)
	output := filepath.Join(base, "enrollment.json")
	signArgs := []string{"management-enrollment-sign", "--key", ownerFile, "--input", input, "--output", output}
	_, e = run(ctx, signArgs)
	must(e)
	if _, e = run(ctx, signArgs); !errors.Is(e, os.ErrExist) {
		t.Fatal("signer overwrote grant", e)
	}
	profile := worker.ReportProfile{Format: worker.ReportProfileFormat, Endpoint: "https://127.0.0.1:1", Identity: node, Domain: domain, EnrollmentFile: output, Schedule: management.DispatchConfig{Format: management.DispatchFormat, Revision: 1, Enabled: false, IntervalSeconds: 60, RetrySeconds: 5, AttemptSeconds: 2}}
	profileFile := put("report.json", profile)
	command := func(name string) (any, error) {
		return run(ctx, []string{name, "--bootstrap", bootstrap, "--input", profileFile})
	}
	result, e := command("worker-report-init")
	must(e)
	if result.(management.DispatchStatus).Phase != "PAUSED" {
		t.Fatal("initial schedule not paused")
	}
	if _, e = command("worker-report-init"); !errors.Is(e, management.ErrConflict) {
		t.Fatal("reinitialized reporting counter", e)
	}
	result, e = command("worker-report-status")
	must(e)
	queue := result.(map[string]any)["queue"].(management.ReportQueueStatus)
	if queue.Sequence != 0 || queue.EnrollmentRevision != 1 || !queue.EnrollmentActive {
		t.Fatal(queue)
	}
	bounded, cancel := context.WithTimeout(ctx, 160*time.Millisecond)
	defer cancel()
	_, e = run(bounded, []string{"worker-report-loop", "--bootstrap", bootstrap, "--input", profileFile})
	if !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("paused foreground loop did not stop", e)
	}
	enrollment.Revision++
	enrollment.Revoked = true
	input = put("enrollment-input2.json", enrollment)
	output = filepath.Join(base, "enrollment2.json")
	_, e = run(ctx, []string{"management-enrollment-sign", "--key", ownerFile, "--input", input, "--output", output})
	must(e)
	profile.EnrollmentFile = output
	put("report.json", profile)
	result, e = command("worker-report-status")
	must(e)
	if result.(map[string]any)["queue"].(management.ReportQueueStatus).EnrollmentRevision != 1 {
		t.Fatal("profile silently changed grant")
	}
	result, e = command("worker-report-renew")
	must(e)
	queue = result.(management.ReportQueueStatus)
	if queue.EnrollmentRevision != 2 || queue.EnrollmentActive || queue.Sequence != 0 {
		t.Fatal("explicit revoke lost counter", queue)
	}
	profile.Schedule.Revision++
	profile.Schedule.RetrySeconds = 10
	put("report.json", profile)
	_, e = command("worker-report-set")
	must(e)
	help, e := run(ctx, []string{"help"})
	must(e)
	encoded, e := json.Marshal(help)
	must(e)
	if !bytes.Contains(encoded, []byte("worker-report-loop")) || !bytes.Contains(encoded, []byte("management-enrollment-sign")) {
		t.Fatal("report commands absent from help")
	}
}
