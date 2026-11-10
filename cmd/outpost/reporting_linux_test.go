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
	"github.com/nd4y/outpost/internal/upload"
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
	writer, writerKey := key()
	maintenance, maintenanceKey := key()
	planner, plannerKey := key()
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
	{
		trust := cfg.Domains[0].Trust
		dir := filepath.Join(worker.DomainDirectory(filepath.Join(root, "worker"), trust), "replica")
		must(os.MkdirAll(dir, 0700))
		r, e := generation.Open(dir, trust, true)
		must(e)
		manifest, payload := []byte("kit fixture"), []byte("ciphertext fixture")
		rootRef := generation.Object{ID: storage.Hash(manifest), Bytes: len(manifest)}
		payloadRef := generation.Object{ID: storage.Hash(payload), Bytes: len(payload)}
		raw, e := generation.SignCatalog(generation.Catalog{
			Format: generation.Format, Domain: domain, Repository: repository, Epoch: trust.Epoch,
			Sequence: 1, SnapshotUnix: now.Unix(), Policy: cfg.Revision, KitFormat: generation.KitFormat,
			Kits: []generation.Kit{{
				File: storage.Hash([]byte("file")), Version: storage.Hash([]byte("version")),
				Root: rootRef, Objects: []generation.Object{payloadRef},
			}},
		}, writerKey)
		must(e)
		objects := map[string][]byte{rootRef.ID: manifest, payloadRef.ID: payload}
		id, e := r.Receive(ctx, raw, func(ref generation.Object) ([]byte, error) { return objects[ref.ID], nil })
		must(e)
		must(r.Close())
		grant := generation.RetentionProtection{
			Format: generation.RetentionProtectionFormat, Node: node, Domain: domain, Repository: repository,
			Epoch: trust.Epoch, Operation: storage.Hash([]byte("retention")), Generation: id,
			Action: "HOLD", NotBefore: cfg.NotBefore, ExpiresUnix: cfg.ExpiresUnix,
		}
		maintenanceFile := put("maintenance.json", map[string]any{"privateKey": maintenanceKey})
		apply := func(filename, state string) generation.RetentionProtectionReceipt {
			input := put(filename+"-draft.json", grant)
			signed := filepath.Join(base, filename+"-signed.json")
			_, e := run(ctx, []string{"retention-protection-sign", "--key", maintenanceFile, "--input", input, "--output", signed})
			must(e)
			result, e := run(ctx, []string{"replica-retention-protect", "--bootstrap", bootstrap, "--domain", domain, "--input", signed})
			must(e)
			raw, e := json.Marshal(result)
			must(e)
			receipt, e := generation.VerifyRetentionProtectionReceipt(raw, node)
			must(e)
			if receipt.State != state || receipt.Operation != grant.Operation || receipt.Generation != grant.Generation {
				t.Fatal(receipt)
			}
			return receipt
		}
		held := apply("hold", "HELD")
		grant.Action, grant.HoldDigest = "RELEASE", held.HoldDigest
		released := apply("release", "RELEASED")
		if released.Revision <= held.Revision {
			t.Fatal("release did not advance the replica revision")
		}
		grant.Action, grant.Generation, grant.HoldDigest = "CLOSE", "", ""
		grant.Operation = storage.Hash([]byte("retirement operation"))
		closed := apply("close", "CLOSED")
		if closed.Revision <= released.Revision {
			t.Fatal("closure did not advance the replica revision")
		}
		// Prepare an expired, locally pinned queue without contacting its target.
		r, e = generation.Open(dir, trust, false)
		must(e)
		defer r.Close()
		op := storage.Hash([]byte("expired upload"))
		profile := storage.Profile{Kind: "webdav", Endpoint: "https://target.invalid", Namespace: storage.Hash([]byte(domain + "/" + repository)),
			MaxObjectBytes: 64 << 10, Concurrency: 1, RequestsPerSecond: 1000, Attempts: 2, TimeoutMillis: 3000, CredentialScope: "namespace", NoDelete: true}
		limits := upload.QueueLimits{MaxJobs: 1, Parallel: 1, AttemptMillis: 300000, RetryBaseMillis: 1000, RetryMaxMillis: 60000}
		queueDir := filepath.Join(filepath.Dir(dir), "uploads", op)
		must(os.MkdirAll(queueDir, 0700))
		q, e := upload.OpenQueue(queueDir, node, upload.Authority{Generation: trust, Planner: planner}, limits, true)
		must(e)
		end := time.Now().Add(5 * time.Second).Unix()
		plan, e := upload.Build(ctx, r, id, upload.Plan{Format: upload.Format, Operation: op, Profile: profile, AllowExternal: true,
			AllowedClasses: []string{"trusted"}, Workers: []upload.Worker{{ID: node, Class: "trusted", PublicKey: nodeKey}},
			StartMillis: time.Now().UnixMilli(), ExpiresUnix: end, SlotMillis: 1000}, plannerKey)
		must(e)
		must(q.Enqueue(ctx, r, plan))
		must(q.Close())
		time.Sleep(time.Until(time.Unix(end, 0)))

		draft := filepath.Join(base, "upload-abandonment.json")
		grantFile := filepath.Join(base, "upload-abandonment-signed.json")
		_, e = run(ctx, []string{"worker-upload-abandon-preview", "--bootstrap", bootstrap, "--domain", domain, "--operation", op, "--output", draft})
		must(e)
		_, e = run(ctx, []string{"upload-abandon-sign", "--key", maintenanceFile, "--input", draft, "--output", grantFile})
		must(e)
		abandonArgs := []string{"worker-upload-abandon", "--bootstrap", bootstrap, "--domain", domain, "--operation", op, "--input", grantFile}
		result, e := run(ctx, abandonArgs)
		must(e)
		receipt := result.(upload.AbandonmentReceipt)
		if receipt.Operation != op || receipt.Plan != storage.Hash(plan) || receipt.ReleasedUnix < end {
			t.Fatal(receipt)
		}
		again, e := run(ctx, abandonArgs)
		must(e)
		if again.(upload.AbandonmentReceipt) != receipt {
			t.Fatal("CLI replay changed abandonment receipt")
		}
		after, e := r.Status(ctx)
		must(e)
		if len(after.Pins) != 0 {
			t.Fatal("upload pins remained", after.Pins)
		}
		must(r.VerifyComplete(ctx, id))
	}
	checkCLICommands(t, base, bootstrap, ownerFile, cfg, ownerKey)
}
