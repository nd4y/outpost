package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/sourceagent"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"github.com/nd4y/outpost/internal/worker"
)

// This opt-in functional test starts the independently selected distribution,
// including both receiver worker-run loops. A single private test namespace is
// not a physical failure domain or evidence of the distribution's isolation.
// Those controls and physical 100 GiB acceptance have separate fixtures.
func TestCLIProcessSourceAndOutboundFollowerKeepIndependentHistory(t *testing.T) {
	if os.Getenv("OUTPOST_CLI_PROCESS_FLOW") != "1" {
		t.Skip("independently selected distribution and admitted test root required")
	}
	binary := os.Getenv("OUTPOST_FLOW_CURRENT_CLI")
	expected, revision := os.Getenv("OUTPOST_FLOW_CURRENT_SHA256"), os.Getenv("OUTPOST_FLOW_REVISION")
	root := os.Getenv("OUTPOST_TEST_ROOT")
	resolved, err := filepath.EvalSymlinks(root)
	containerMust(t, err)
	if !filepath.IsAbs(root) || resolved != root || !filepath.IsAbs(binary) || !storage.ID(expected) || len(revision) != 40 {
		t.Fatal("explicit selected CLI digest/revision and real absolute fixture root required")
	}
	decoded, err := hex.DecodeString(revision)
	containerMust(t, err)
	if len(decoded) != 20 {
		t.Fatal("invalid selected executable revision")
	}
	raw, err := os.ReadFile(binary)
	containerMust(t, err)
	if storage.Hash(raw) != expected {
		t.Fatal("independently selected executable digest mismatch")
	}
	base, err := os.MkdirTemp(root, "cli-process-flow-")
	containerMust(t, err)
	t.Cleanup(func() {
		if !t.Failed() {
			containerMust(t, os.RemoveAll(base))
		}
	})
	logs := filepath.Join(base, "logs")
	containerMust(t, os.Mkdir(logs, 0700))
	run := func(success bool, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
		defer cancel()
		dir, err := os.MkdirTemp(logs, "command-")
		containerMust(t, err)
		path := filepath.Join(dir, "output.log")
		output, err := newCLIFlowLog(path)
		containerMust(t, err)
		cmd := exec.CommandContext(ctx, binary, args...)
		cmd.Stdout, cmd.Stderr = output, output
		runErr := cmd.Run()
		containerMust(t, output.Close())
		if ctx.Err() != nil || (runErr == nil) != success {
			t.Fatalf("selected CLI %s unexpected exit (output withheld): %v", args[0], runErr)
		}
		if output.Truncated() {
			t.Fatal("selected CLI result exceeds test bound")
		}
		out, err := os.ReadFile(path)
		containerMust(t, err)
		return out
	}
	var version struct {
		Revision string
		Result   struct{ Revision string }
	}
	containerMust(t, json.Unmarshal(run(true, "version"), &version))
	if version.Revision != revision || version.Result.Revision != revision {
		t.Fatal("actual executable version differs from independent selection")
	}
	write := func(name string, value any) string {
		t.Helper()
		path := filepath.Join(base, name)
		containerJSON(t, path, value)
		return path
	}
	writeBytes := func(name string, raw []byte) string {
		t.Helper()
		path := filepath.Join(base, name)
		containerMust(t, writeNew(path, raw))
		return path
	}
	now := time.Now()
	caPub, caKey := containerKey(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	containerMust(t, err)
	caPath := writeBytes("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("fixture CA rejected")
	}
	type identity struct {
		id, certPath, keyPath string
		cert                  tls.Certificate
	}
	newIdentity := func(name string, serial int64) identity {
		t.Helper()
		pub, key := containerKey(t)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, e := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
		containerMust(t, e)
		pkcs, e := x509.MarshalPKCS8PrivateKey(key)
		containerMust(t, e)
		cp, kp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs})
		cert, e := tls.X509KeyPair(cp, kp)
		containerMust(t, e)
		parsed, e := x509.ParseCertificate(der)
		containerMust(t, e)
		return identity{peer.Identity(parsed), writeBytes(name+".pem", cp), writeBytes(name+"-key.pem", kp), cert}
	}
	src, a, b, center := newIdentity("source", 2), newIdentity("a", 3), newIdentity("b", 4), newIdentity("center", 5)
	var documents sync.Map
	var centerRequests atomic.Int64
	cp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		id := peer.Identity(r.TLS.PeerCertificates[0])
		document, ok := documents.Load(id)
		if !ok || r.URL.Path != "/v1/config/"+id {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		centerRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write(document.([]byte))
	}))
	cp.TLS, err = peer.AuthenticatedServerTLS(center.cert, roots, center.id)
	containerMust(t, err)
	cp.StartTLS()
	t.Cleanup(cp.Close)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	containerMust(t, err)
	address := listener.Addr().String()
	containerMust(t, listener.Close())
	endpoint := "https://" + address
	ownerPub, ownerKey := containerKey(t)
	ownerPath := write("owner-signing.json", map[string]any{"privateKey": ownerKey})
	dataOwner, err := filekit.NewOwner()
	containerMust(t, err)
	dataPath := filepath.Join(base, "data-owner.json")
	containerMust(t, filekit.WriteOwner(dataPath, dataOwner))
	recoveryOwner := dataOwner
	recoveryOwner.SigningKey = nil
	recoveryPath := filepath.Join(base, "recovery-owner.json")
	containerMust(t, filekit.WriteOwner(recoveryPath, recoveryOwner))
	writerPub, writerKey := containerKey(t)
	maintenance, _ := containerKey(t)
	planner, _ := containerKey(t)
	trust := generation.Trust{Domain: dataOwner.Domain, Repository: storage.Hash([]byte("actual-cli-flow")), Epoch: 1, Writer: writerPub, Maintenance: maintenance}
	trustPath := write("recovery-trust.json", trust)
	writerPath := write("writer.json", map[string]any{"privateKey": writerKey})
	grant := ingress.Authority{Format: ingress.AuthorityFormat, Tenant: storage.Hash([]byte("cli-flow-tenant")), Profile: storage.Hash([]byte("cli-flow-profile")), Source: src.id, Ingress: a.id, Revision: 1, NotBefore: now.Unix() - 10, ExpiresUnix: now.Add(time.Hour).Unix(), Trust: trust, MaxBytes: 64 << 20, MaxObjects: 128}
	unsigned := write("authority-input.json", grant)
	authorityPath := filepath.Join(base, "authority.json")
	run(true, "source-authority-sign", "--key", ownerPath, "--input", unsigned, "--output", authorityPath)
	authority, err := os.ReadFile(authorityPath)
	containerMust(t, err)
	local := func(name string, node identity) worker.Bootstrap {
		t.Helper()
		dir := filepath.Join(base, name+"-volume")
		containerMust(t, os.Mkdir(dir, 0700))
		probe, e := volume.Probe(t.Context(), dir)
		containerMust(t, e)
		binding, e := volume.Enroll(t.Context(), dir, probe, node.id, 1)
		containerMust(t, e)
		return worker.Bootstrap{Format: worker.BootstrapFormat, Volume: binding, Directory: filepath.Join(dir, "runtime"), Node: node.id, Owner: ownerPub, CertificateFile: node.certPath, PrivateKeyFile: node.keyPath, CAFile: caPath}
	}
	aLocal, bLocal, sourceLocal := local("a", a), local("b", b), local("source", src)
	aLocal.Listen = address
	for _, bootstrap := range []*worker.Bootstrap{&aLocal, &bLocal} {
		bootstrap.ControlEndpoint, bootstrap.ControlIdentity = cp.URL, center.id
	}
	aPath, bPath := write("a-bootstrap.json", aLocal), write("b-bootstrap.json", bLocal)
	tree := filepath.Join(base, "source-tree")
	containerMust(t, os.Mkdir(tree, 0700))
	input := filepath.Join(tree, "данные.bin")
	oldBytes := make([]byte, 2<<20)
	_, err = rand.Read(oldBytes)
	containerMust(t, err)
	containerMust(t, os.WriteFile(input, oldBytes, 0640))
	containerMust(t, os.Link(input, filepath.Join(tree, "alias.bin")))
	mtime := time.Unix(1730000000, 123456789)
	containerMust(t, os.Chtimes(input, mtime, mtime))
	origin := storage.Hash([]byte("cli-flow-origin"))
	view, err := capture.ProbeTree(t.Context(), tree, origin)
	containerMust(t, err)
	sourceBootstrap := sourceagent.Bootstrap{Format: sourceagent.Format, Local: sourceLocal, Profile: capture.Profile{ID: grant.Profile, Origin: origin, Consistency: "best-effort", Selection: source.Selection{Rules: []policy.Rule{{Prefix: ".", Domain: trust.Domain}}, Domains: map[string]bool{trust.Domain: true}, EntryLimit: 128}, MaxSourceBytes: 16 << 20, MinimumCopies: 1, CopyTargets: []string{a.id}}, Tree: view, DataKeyFile: dataPath, WriterKeyFile: writerPath, AuthorityFile: authorityPath, Endpoint: endpoint, Limits: diskbudget.Limits{Capacity: 64 << 20, Reserve: 8 << 20, Spool: 16 << 20, Telemetry: 1 << 20}}
	sourcePath := write("source-bootstrap.json", sourceBootstrap)
	rule := control.Replication{Domain: trust.Domain, From: a.id, To: b.id, Mode: "pull", Epoch: 1, PeerRevision: 1}
	domain := control.Domain{Trust: trust, Planner: planner, Placement: policy.Placement{Domain: trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{a.id, b.id}, Transit: []string{src.id}, Edges: []policy.Edge{{From: src.id, To: a.id, Mode: "push"}, {From: a.id, To: b.id, Mode: "pull"}}}}
	for index, bootstrap := range []struct {
		id, path string
	}{{a.id, aPath}, {b.id, bPath}} {
		config := control.Config{Format: control.Format, Node: bootstrap.id, Revision: 1, NotBefore: grant.NotBefore, ExpiresUnix: grant.ExpiresUnix, Nodes: []policy.Node{{ID: src.id, Class: "trusted"}, {ID: a.id, Class: "trusted", Endpoint: endpoint}, {ID: b.id, Class: "trusted"}}, Domains: []control.Domain{domain}, Replication: []control.Replication{rule}, Limits: control.Limits{Parallel: 1, AttemptMillis: 30000, PollSeconds: 1, CapacityBytes: 128 << 20, ReserveBytes: 8 << 20, SpoolBytes: 16 << 20, TelemetryBytes: 1 << 20}}
		if index == 0 {
			config.Ingress = []json.RawMessage{authority}
		}
		inputPath := write(bootstrap.id+"-policy-input.json", config)
		signed := filepath.Join(base, bootstrap.id+"-policy.json")
		run(true, "config-sign", "--key", ownerPath, "--input", inputPath, "--output", signed)
		raw, e := os.ReadFile(signed)
		containerMust(t, e)
		documents.Store(bootstrap.id, raw)
		run(true, "worker-init", "--bootstrap", bootstrap.path)
		run(true, "config-apply", "--bootstrap", bootstrap.path, "--input", signed)
	}
	run(true, "source-init", "--bootstrap", sourcePath)
	sourceStatus := func(flags ...string) sourceagent.Status {
		t.Helper()
		var out struct{ Result sourceagent.Status }
		args := append([]string{"source-status", "--bootstrap", sourcePath}, flags...)
		containerMust(t, json.Unmarshal(run(true, args...), &out))
		return out.Result
	}
	workerStatus := func(path string) worker.Status {
		t.Helper()
		var out struct{ Result worker.Status }
		containerMust(t, json.Unmarshal(run(true, "worker-status", "--bootstrap", path), &out))
		return out.Result
	}
	wait := func(process *cliFlowProcess, ready func() bool) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			if !process.Running() {
				t.Fatal("selected worker-run exited before expected durable state")
			}
			if ready() {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("actual CLI data-flow exceeded fixture deadline")
	}
	run(true, "source-next", "--bootstrap", sourcePath)
	before := sourceStatus()
	run(false, "source-run", "--bootstrap", sourcePath)
	blocked := sourceStatus()
	if blocked.Phase == "COMPLETE" || blocked.Operation != before.Operation || blocked.Milestones != nil && blocked.Milestones.ProviderReleaseUnix != 0 {
		t.Fatal("unavailable required receiver released or replaced source intent")
	}
	primary := startCLIFlowProcess(t, binary, logs, "worker-run", "--bootstrap", aPath)
	wait(primary, func() bool { return workerStatus(aPath).Phase == "ACTIVE" && centerRequests.Load() > 0 })
	var observedRun struct{ Result sourceagent.Status }
	containerMust(t, json.Unmarshal(run(true, "source-run", "--bootstrap", sourcePath, "--observe-direct-source-bodies"), &observedRun))
	first := sourceStatus()
	if first.Phase != "COMPLETE" || first.Sequence != 1 || first.Milestones == nil || first.Milestones.FirstReplicaVerifiedUnix == 0 {
		t.Fatal("actual source/receiver processes did not publish first generation")
	}
	if first.CaptureMeasurements != nil {
		t.Fatal("ordinary source-status included opt-in measurements")
	}
	bodies := observedRun.Result.OutgoingIngressObjectBodies
	if observedRun.Result.Generation != first.Generation || bodies == nil || bodies.Retention != "CURRENT_PROCESS_RUN" ||
		len(bodies.Samples) != 1 || bodies.Samples[0].TransportReadPutBodyBytes < 1 || first.OutgoingIngressObjectBodies != nil {
		t.Fatal("direct PUT observation escaped its source-run process or was missing")
	}
	run(false, "source-status", "--bootstrap", sourcePath, "--observe-direct-source-bodies")
	primary.Stop(t)
	measured := sourceStatus("--capture-measurements")
	m := measured.CaptureMeasurements
	if measured.Generation != first.Generation || m == nil || m.IncludedEntries < 1 || m.SourceReadBytes != int64(len(oldBytes)) ||
		m.NewPayloadBytes <= 0 || m.NewMetadataBytes <= 0 || m.NewObjects <= 0 {
		t.Fatalf("source-status could not read local receipts with the receiver stopped: %+v", m)
	}
	primary = startCLIFlowProcess(t, binary, logs, "worker-run", "--bootstrap", aPath)
	wait(primary, func() bool { return workerStatus(aPath).Phase == "ACTIVE" })
	newBytes := bytes.Clone(oldBytes)
	copy(newBytes[len(newBytes)/2:], bytes.Repeat([]byte{0x57}, 8<<10))
	containerMust(t, os.WriteFile(input, newBytes, 0640))
	secondMtime := mtime.Add(time.Second)
	containerMust(t, os.Chtimes(input, secondMtime, secondMtime))
	run(true, "source-next", "--bootstrap", sourcePath)
	run(true, "source-run", "--bootstrap", sourcePath)
	second := sourceStatus()
	if second.Phase != "COMPLETE" || second.Sequence != 2 || second.Generation == first.Generation {
		t.Fatal("actual source/receiver processes did not retain successive generations")
	}
	cp.Close()
	for _, path := range []string{tree, sourceLocal.Volume.Root, sourcePath, dataPath, writerPath, ownerPath, authorityPath, src.keyPath} {
		containerMust(t, os.RemoveAll(path))
	}
	if bLocal.Listen != "" || domain.Placement.HasEdge(src.id, b.id, "push") {
		t.Fatal("outbound-only fixture unexpectedly grants source/follower route")
	}
	follower := startCLIFlowProcess(t, binary, logs, "worker-run", "--bootstrap", bPath)
	firstJob, secondJob := rule.Job(trust, first.Generation), rule.Job(trust, second.Generation)
	caughtUp := func() bool {
		s := workerStatus(bPath)
		return s.Phase == "ACTIVE" && s.Jobs[firstJob.Operation].Phase == "COMPLETE" && s.Jobs[secondJob.Operation].Phase == "COMPLETE"
	}
	wait(follower, caughtUp)
	prior := workerStatus(bPath)
	follower.stopWithSignal(t, syscall.SIGINT)
	primary.Stop(t)
	follower = startCLIFlowProcess(t, binary, logs, "worker-run", "--bootstrap", bPath)
	wait(follower, caughtUp)
	after := workerStatus(bPath)
	for _, job := range []control.Job{firstJob, secondJob} {
		if !bytes.Equal(prior.Jobs[job.Operation].Receipt, after.Jobs[job.Operation].Receipt) || prior.Jobs[job.Operation].Attempts != after.Jobs[job.Operation].Attempts {
			t.Fatal("offline executable restart changed accepted receipt or repeated completed work")
		}
	}
	follower.Stop(t)
	for _, path := range []string{tree, sourceLocal.Volume.Root, dataPath, writerPath, ownerPath, authorityPath, src.keyPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("source/runtime/operational secret still present before offline recovery")
		}
	}
	restores := 0
	for index, bootstrap := range []worker.Bootstrap{aLocal, bLocal} {
		store := filepath.Join(worker.DomainDirectory(bootstrap.Directory, trust), "replica")
		immutable := filepath.Join(base, "immutable-"+bootstrap.Node)
		containerMust(t, os.Mkdir(immutable, 0700))
		for _, category := range []string{"catalogs", "objects"} {
			containerMust(t, os.Mkdir(filepath.Join(immutable, category), 0700))
			entries, err := os.ReadDir(filepath.Join(store, category))
			containerMust(t, err)
			for _, entry := range entries {
				if entry.Type() != 0 || !storage.ID(entry.Name()) {
					t.Fatal("unexpected immutable replica entry")
				}
				containerMust(t, os.Link(filepath.Join(store, category, entry.Name()), filepath.Join(immutable, category, entry.Name())))
			}
		}
		for phase, item := range []struct {
			generation string
			bytes      []byte
			mtime      time.Time
		}{{first.Generation, oldBytes, mtime}, {second.Generation, newBytes, secondMtime}} {
			output := filepath.Join(base, "restore-"+bootstrap.Node+"-"+item.generation)
			run(true, "restore-replica", "--key", recoveryPath, "--trust", trustPath, "--store", immutable, "--generation", item.generation, "--output", output)
			actual, err := os.ReadFile(filepath.Join(output, "данные.bin"))
			containerMust(t, err)
			info, err := os.Stat(filepath.Join(output, "данные.bin"))
			containerMust(t, err)
			alias, err := os.Stat(filepath.Join(output, "alias.bin"))
			containerMust(t, err)
			if !bytes.Equal(actual, item.bytes) || info.Mode().Perm() != 0640 || !info.ModTime().Equal(item.mtime) || !os.SameFile(info, alias) || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) || info.Sys().(*syscall.Stat_t).Gid != uint32(os.Getgid()) {
				t.Fatalf("actual offline reader bytes/attributes differ for holder%d phase%d", index, phase)
			}
			restores++
		}
	}
	report := map[string]any{"format": "outpost-cli-process-flow-evidence-1", "revision": revision, "binarySHA256": expected, "bytesPerVersion": len(oldBytes), "versions": 2, "receivers": 2, "independentMaterializedRestores": restores, "initialRequiredReceiverRefusal": true, "sourceAbsentBeforeFollowerCatchUp": true, "controlPlaneClosedBeforeFollowerStart": true, "outboundOnlyFollower": true, "restartReceiptsUnchanged": true, "sourceAuthorityAndRuntimeAbsentAtRestore": true, "attributesVerified": []string{"bytes", "mode", "uid", "gid", "nanosecond-mtime", "hardlink"}, "fullProductAcceptance": false, "scope": "Actual selected source and two worker-run CLI processes in one isolated fixture namespace; immutable-only hardlink views share physical ciphertext. No physical failure-domain, strict per-role mount isolation, 100GiB, cloud or production acceptance."}
	oldSum, newSum := sha256.Sum256(oldBytes), sha256.Sum256(newBytes)
	report["oldSHA256"], report["newSHA256"] = hex.EncodeToString(oldSum[:]), hex.EncodeToString(newSum[:])
	if path := os.Getenv("OUTPOST_CLI_FLOW_REPORT"); path != "" {
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		containerMust(t, err)
		if !filepath.IsAbs(path) || parent != filepath.Dir(path) || strings.Contains(filepath.Base(path), string(os.PathSeparator)) {
			t.Fatal("explicit real report parent required")
		}
		containerJSON(t, path, report)
	}
	if t.Failed() {
		return
	}
	t.Log("CLI_PROCESS_FLOW_SHUTDOWN signals=SIGTERM,SIGINT")
	t.Logf("CLI_PROCESS_FLOW_PASS revision=%s bytes=%d versions=2 workers=2 independent-immutable-restores=%d source-and-center-offline=true", revision, len(oldBytes), restores)
}

func TestCLIProcessFlowSelectionRefusesBeforeFixture(t *testing.T) {
	if os.Getenv("OUTPOST_CLI_PROCESS_FLOW") != "1" {
		t.Skip("independently selected distribution and admitted test root required")
	}
	root := os.Getenv("OUTPOST_TEST_ROOT")
	resolved, err := filepath.EvalSymlinks(root)
	containerMust(t, err)
	if !filepath.IsAbs(root) || resolved != root {
		t.Fatal("real absolute fixture root required")
	}
	base, err := os.MkdirTemp(root, "cli-flow-selection-")
	containerMust(t, err)
	t.Cleanup(func() {
		if !t.Failed() {
			containerMust(t, os.RemoveAll(base))
		}
	})
	sha, revision := os.Getenv("OUTPOST_FLOW_CURRENT_SHA256"), os.Getenv("OUTPOST_FLOW_REVISION")
	for _, test := range []struct {
		name, digest, revision, marker string
	}{
		{"wrong-digest", strings.Repeat("0", 64), revision, "independently selected executable digest mismatch"},
		{"wrong-revision", sha, strings.Repeat("0", 40), "actual executable version differs from independent selection"},
	} {
		t.Run(test.name, func(t *testing.T) {
			work := filepath.Join(base, test.name)
			containerMust(t, os.Mkdir(work, 0700))
			outputPath := filepath.Join(base, test.name+".log")
			output, err := newCLIFlowLog(outputPath)
			containerMust(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCLIProcessSourceAndOutboundFollowerKeepIndependentHistory$", "-test.count=1", "-test.timeout=40s", "-test.v")
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, "OUTPOST_TEST_ROOT=") && !strings.HasPrefix(value, "OUTPOST_FLOW_CURRENT_SHA256=") && !strings.HasPrefix(value, "OUTPOST_FLOW_REVISION=") && !strings.HasPrefix(value, "OUTPOST_CLI_FLOW_REPORT=") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "OUTPOST_TEST_ROOT="+work, "OUTPOST_FLOW_CURRENT_SHA256="+test.digest, "OUTPOST_FLOW_REVISION="+test.revision)
			cmd.Stdout, cmd.Stderr = output, output
			runErr := cmd.Run()
			containerMust(t, output.Close())
			raw, err := os.ReadFile(outputPath)
			containerMust(t, err)
			exit, ok := runErr.(*exec.ExitError)
			if ctx.Err() != nil || !ok || exit.ExitCode() != 1 || output.Truncated() || !bytes.Contains(raw, []byte(test.marker)) || bytes.Contains(raw, []byte("CLI_PROCESS_FLOW_PASS")) || bytes.Contains(raw, []byte("--- SKIP:")) {
				t.Fatal("wrong selection did not produce the expected pre-initialization refusal")
			}
			containerMust(t, filepath.WalkDir(work, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				name := entry.Name()
				if strings.HasSuffix(name, ".pem") || strings.Contains(name, "bootstrap") || strings.HasSuffix(name, "-volume") || name == "source-tree" || name == "authority.json" {
					t.Fatal("refused selection initialized fixture identities or runtime")
				}
				return nil
			}))
		})
	}
}
