package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
)

func TestReplacementDatasetRebuildActualCLI(t *testing.T) {
	binary := os.Getenv("OUTPOST_DATASET_REBUILD_CLI")
	if binary == "" {
		t.Skip("independently selected native CLI required")
	}
	revision := os.Getenv("OUTPOST_DATASET_REBUILD_REVISION")
	decoded, err := hex.DecodeString(revision)
	if err != nil || len(decoded) != 20 {
		t.Fatal("explicit source revision required")
	}
	info, err := os.Lstat(binary)
	must(t, err)
	if !filepath.IsAbs(binary) || !info.Mode().IsRegular() || info.Size() > 128<<20 {
		t.Fatal("bounded regular selected executable required")
	}
	executable, err := os.ReadFile(binary)
	must(t, err)
	if expected := os.Getenv("OUTPOST_DATASET_REBUILD_SHA256"); !storage.ID(expected) || storage.Hash(executable) != expected {
		t.Fatal("selected executable digest differs")
	}
	executable = nil
	run := func(result any, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, args...)
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			t.Fatalf("CLI %s failed: %v: %.2000s", args[0], err, stderr.String())
		}
		var envelope struct {
			Format   string          `json:"format"`
			Revision string          `json:"revision"`
			Result   json.RawMessage `json:"result"`
		}
		must(t, json.Unmarshal(stdout.Bytes(), &envelope))
		if envelope.Format != "outpost-cli-1" || envelope.Revision != revision || len(envelope.Result) == 0 {
			t.Fatal("CLI source/envelope binding differs")
		}
		if result != nil {
			must(t, json.Unmarshal(envelope.Result, result))
		}
	}
	run(nil, "version")
	f := newFixture(t)
	f.cfg.Nodes[2].Class = "trusted"
	f.domain.Placement.AllowedClasses = []string{"trusted"}
	f.cfg.Limits.AttemptMillis = 60000
	old := f.nodes[2]
	oldBinding := bindFixture(t, f, old)
	var replacement atomic.Value
	var unavailable atomic.Bool
	blocked := make(chan struct{})
	var blockedOnce sync.Once
	var requestMu sync.Mutex
	var requested []string
	server := f.endpoint(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if id, ok := replacement.Load().(string); ok && r.TLS != nil && len(r.TLS.PeerCertificates) != 0 && peer.Identity(r.TLS.PeerCertificates[0]) == id {
				requestMu.Lock()
				if len(requested) >= 256 {
					requestMu.Unlock()
					http.Error(w, "fixture request budget", http.StatusServiceUnavailable)
					return
				}
				requested = append(requested, r.URL.Path)
				requestMu.Unlock()
				if unavailable.Load() {
					blockedOnce.Do(func() { close(blocked) })
					http.Error(w, "controlled holder outage", http.StatusServiceUnavailable)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	ctx := t.Context()
	push, pull := f.rules()
	f.replicationConfig(t, 0, 1, push)
	f.replicationConfig(t, 1, 1, push, pull)
	f.replicationConfig(t, 2, 1, pull)
	stopB := start(t, f.nodes[1])
	stopA := start(t, f.nodes[0])
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[0], push.Job(f.domain.Trust, f.generation).Operation) })
	store, err := filekit.OpenStore(filepath.Join(f.base, "source-kit"), f.dataOwner, false)
	must(t, err)
	changed := bytes.Clone(f.content)
	for i := 64 << 10; i < 72<<10; i++ {
		changed[i] ^= 0xff
	}
	input := filepath.Join(f.base, "next-input")
	must(t, os.WriteFile(input, changed, 0640))
	version, err := store.Backup(ctx, input, filekit.BackupOptions{Names: []string{"dataset/данные.bin"}})
	must(t, err)
	f.nodes[0].mu.Lock()
	source := f.nodes[0].active.domains[f.domain.Trust.Domain].replica
	f.nodes[0].mu.Unlock()
	second, err := generation.Seal(ctx, store, []string{version.Version}, source, generation.Catalog{Format: generation.Format, Domain: f.domain.Trust.Domain, Repository: f.domain.Trust.Repository, Epoch: 1, Sequence: 2, Parent: f.generation, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, f.writer)
	must(t, err)
	must(t, store.Close())
	waitFor(t, 90*time.Second, func() bool { return complete(f.nodes[0], push.Job(f.domain.Trust, second).Operation) })
	stopOld := start(t, old)
	waitFor(t, 90*time.Second, func() bool {
		return complete(old, pull.Job(f.domain.Trust, f.generation).Operation) && complete(old, pull.Job(f.domain.Trust, second).Operation)
	})
	stopOld()
	stopA()
	must(t, os.RemoveAll(filepath.Join(f.base, "source-kit")))
	must(t, os.Remove(filepath.Join(f.base, "input")))
	must(t, os.Remove(input))
	// Hold the entire old dataset, including its runtime, index and receipts.
	// This is logical dataset loss on the admitted filesystem, not a cold boot.
	must(t, os.Rename(oldBinding.Root, oldBinding.Root+"-unavailable"))
	if err := oldBinding.Check(ctx, old.dir, false); !errors.Is(err, volume.ErrUnavailable) {
		t.Fatal("lost dataset was admitted", err)
	}
	oldConfig := f.cfg
	oldConfig.Node, oldConfig.Revision = old.node, 2
	oldConfig.Domains, oldConfig.Replication, oldConfig.Jobs = []control.Domain{f.domain}, []control.Replication{pull}, nil
	oldRaw, err := control.Sign(oldConfig, f.owner)
	must(t, err)
	if err := old.Accept(ctx, oldRaw); !errors.Is(err, volume.ErrUnavailable) {
		t.Fatal("lost dataset accepted a new configuration", err)
	}
	if _, err := os.Stat(oldBinding.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("lost dataset created a fallback root", err)
	}
	cert, node := f.ca.node(t)
	replacement.Store(node)
	newDomain := f.domain
	newDomain.Placement.Holders = []string{f.nodes[0].node, f.nodes[1].node, node}
	newDomain.Placement.Edges = []policy.Edge{{From: f.nodes[0].node, To: f.nodes[1].node, Mode: "push"}, {From: f.nodes[1].node, To: node, Mode: "pull"}}
	newPull := control.Replication{Domain: f.domain.Trust.Domain, From: f.nodes[1].node, To: node, Mode: "pull", Epoch: 1, PeerRevision: 2}
	config := f.cfg
	config.Nodes = append(append([]policy.Node(nil), f.cfg.Nodes[:2]...), policy.Node{ID: node, Class: "trusted"})
	config.Node, config.Revision = f.nodes[1].node, 2
	config.Domains, config.Replication, config.Jobs = []control.Domain{newDomain}, []control.Replication{push, newPull}, nil
	raw, err := control.Sign(config, f.owner)
	must(t, err)
	must(t, f.nodes[1].Accept(ctx, raw))
	waitFor(t, 90*time.Second, func() bool {
		f.nodes[1].mu.Lock()
		defer f.nodes[1].mu.Unlock()
		return f.nodes[1].active != nil && f.nodes[1].active.cfg.Revision == 2
	})
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: f.ca.pool, Certificates: []tls.Certificate{old.cert}}}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/v1/"+f.domain.Trust.Domain+"/inventory", nil)
	must(t, err)
	request.Header.Set("Outpost-Replication", pull.ID(f.domain.Trust))
	request.Header.Set("Outpost-Required-Revision", "1")
	response, err := client.Do(request)
	must(t, err)
	_, err = io.Copy(io.Discard, response.Body)
	must(t, err)
	must(t, response.Body.Close())
	client.CloseIdleConnections()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("withdrawn old identity still read history", response.StatusCode)
	}
	private := filepath.Join(f.base, "replacement private")
	root := filepath.Join(f.base, "replacement empty dataset")
	must(t, os.Mkdir(private, 0700))
	must(t, os.Mkdir(root, 0700))
	probe, bindingFile := filepath.Join(private, "probe.json"), filepath.Join(private, "binding.json")
	run(nil, "volume-probe", "--store", root, "--output", probe)
	run(nil, "volume-enroll", "--store", root, "--input", probe, "--node", node, "--epoch", "1", "--output", bindingFile)
	var binding volume.Binding
	raw, err = os.ReadFile(bindingFile)
	must(t, err)
	must(t, json.Unmarshal(raw, &binding))
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	must(t, err)
	for name, value := range map[string][]byte{"node.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), "node.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), "ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.cert.Raw})} {
		must(t, os.WriteFile(filepath.Join(private, name), value, 0600))
	}
	bootstrap := Bootstrap{Format: BootstrapFormat, Volume: binding, Directory: filepath.Join(root, "worker"), Node: node, Owner: f.owner.Public().(ed25519.PublicKey), CertificateFile: filepath.Join(private, "node.crt"), PrivateKeyFile: filepath.Join(private, "node.key"), CAFile: filepath.Join(private, "ca.crt")}
	raw, err = json.Marshal(bootstrap)
	must(t, err)
	profile := filepath.Join(private, "worker bootstrap.json")
	must(t, os.WriteFile(profile, raw, 0600))
	run(nil, "worker-init", "--bootstrap", profile)
	config.Node, config.Revision, config.Replication = node, 1, []control.Replication{newPull}
	raw, err = control.Sign(config, f.owner)
	must(t, err)
	signed := filepath.Join(private, "signed policy.json")
	must(t, os.WriteFile(signed, raw, 0600))
	run(nil, "config-apply", "--bootstrap", profile, "--input", signed)
	var state Status
	run(&state, "worker-status", "--bootstrap", profile)
	if state.Node != node || len(state.Jobs) != 0 || bootstrap.ControlEndpoint != "" || len(config.Jobs) != 0 {
		t.Fatal("replacement reused runtime or per-generation jobs")
	}
	unavailable.Store(true)
	command := exec.CommandContext(t.Context(), binary, "worker-run", "--bootstrap", profile)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	must(t, command.Start())
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	stopCLI := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		if err := command.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Error(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("worker process failed: %v: %.2000s", err, stderr.String())
			}
		case <-time.After(15 * time.Second):
			_ = command.Process.Kill()
			<-done
			t.Error("worker did not join after SIGTERM")
		}
	}
	t.Cleanup(stopCLI)
	select {
	case <-blocked:
	case <-time.After(30 * time.Second):
		t.Fatal("replacement did not attempt its admitted holder")
	}
	run(&state, "worker-status", "--bootstrap", profile)
	for _, job := range state.Jobs {
		if job.Phase == "COMPLETE" || len(job.Receipt) != 0 {
			t.Fatal("unavailable history claimed an accepted copy")
		}
	}
	unavailable.Store(false)
	firstJob, secondJob := newPull.Job(f.domain.Trust, f.generation), newPull.Job(f.domain.Trust, second)
	deadline := time.Now().Add(90 * time.Second)
	for {
		run(&state, "worker-status", "--bootstrap", profile)
		if state.Jobs[firstJob.Operation].Phase == "COMPLETE" && state.Jobs[secondJob.Operation].Phase == "COMPLETE" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement did not reconstruct retained history")
		}
		time.Sleep(time.Second)
	}
	if len(state.Jobs[firstJob.Operation].Receipt) == 0 || len(state.Jobs[secondJob.Operation].Receipt) == 0 {
		t.Fatal("replacement completion lacks durable receipts")
	}
	if _, reused := state.Jobs[pull.Job(f.domain.Trust, f.generation).Operation]; reused {
		t.Fatal("old identity job receipt reused")
	}
	stopCLI()
	stopB()
	server.Close()
	requestMu.Lock()
	paths := strings.Join(requested, "\n")
	requestMu.Unlock()
	if !strings.Contains(paths, "/"+f.generation+"/catalog") || !strings.Contains(paths, "/"+second+"/catalog") || !strings.Contains(paths, "/objects/") {
		t.Fatal("replacement did not read both catalogs and ciphertext from the surviving holder")
	}
	// The reader receives only immutable files from the new target. Recovery
	// keys are written after all workers/peers have stopped, outside their roots.
	replica := filepath.Join(DomainDirectory(bootstrap.Directory, f.domain.Trust), "replica")
	clean := filepath.Join(f.base, "clean immutable recovery")
	must(t, os.Mkdir(clean, 0700))
	files := 0
	for _, directory := range []string{"catalogs", "objects"} {
		base := filepath.Join(replica, directory)
		must(t, filepath.WalkDir(base, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(replica, path)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Mkdir(filepath.Join(clean, rel), 0700)
			}
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 || files >= 256 {
				return errors.New("unexpected immutable fixture member")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files++
			return os.WriteFile(filepath.Join(clean, rel), data, 0600)
		}))
	}
	owner := f.dataOwner
	owner.SigningKey = nil
	ownerFile, trustFile := filepath.Join(f.base, "offline owner.json"), filepath.Join(f.base, "offline trust.json")
	must(t, filekit.WriteOwner(ownerFile, owner))
	raw, err = json.Marshal(f.domain.Trust)
	must(t, err)
	must(t, os.WriteFile(trustFile, raw, 0600))
	for name, item := range map[string]struct {
		id   string
		data []byte
	}{"old": {f.generation, f.content}, "new": {second, changed}} {
		out := filepath.Join(f.base, "restored "+name)
		var recovered generation.RecoveryReceipt
		run(&recovered, "restore-replica", "--key", ownerFile, "--trust", trustFile, "--store", clean, "--generation", item.id, "--output", out)
		if recovered.Generation != item.id || !recovered.CheckpointMatch {
			t.Fatal("offline restore receipt differs")
		}
		actual, err := os.ReadFile(filepath.Join(out, "dataset/данные.bin"))
		must(t, err)
		if !bytes.Equal(actual, item.data) {
			t.Fatal("independent rebuilt history differs", name)
		}
		t.Logf("DATASET_REBUILD_RESTORE version=%s bytes=%d sha256=%s", name, len(actual), storage.Hash(actual))
	}
	for _, id := range []string{f.generation, second} {
		original, err := os.ReadFile(filepath.Join(DomainDirectory(f.nodes[1].dir, f.domain.Trust), "replica", "catalogs", id))
		must(t, err)
		rebuilt, err := os.ReadFile(filepath.Join(clean, "catalogs", id))
		must(t, err)
		if !bytes.Equal(original, rebuilt) {
			t.Fatal("rebuild changed signed catalog or snapshot age")
		}
	}
	t.Logf("DATASET_REBUILD_PASS revision=%s retainedGenerations=2 immutableFiles=%d sourceAbsent=true oldDatasetFenced=true oldIdentityHTTP=403 unavailableNoComplete=true cachedDiscovery=true gracefulJoin=true offlineIndexAbsent=true", revision, files)
}
