package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

type containerFixture struct {
	Node    string           `json:"node"`
	Version string           `json:"version"`
	Digest  string           `json:"digest"`
	Bytes   int              `json:"bytes"`
	Trust   generation.Trust `json:"trust"`
	Replica string           `json:"replica"`
}

func containerMust(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func containerJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, e := json.Marshal(value)
	containerMust(t, e)
	containerMust(t, writeNew(path, raw))
}
func containerKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	containerMust(t, e)
	return pub, key
}

// Opt-in fixture generation only. Keys and ciphertext stay in the selected
// fresh private HDD directory; ordinary workers never mount recovery-private.
func TestContainerPackagingFixture(t *testing.T) {
	dir := os.Getenv("OUTPOST_CONTAINER_FIXTURE")
	if dir == "" {
		t.Skip("isolated packaging fixture only")
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Base(dir), "container-fixture-") {
		t.Fatal("new absolute fixture directory required")
	}
	if os.Getenv("OUTPOST_CONTAINER_FIXTURE_STAGE") == "seed" {
		raw, e := os.ReadFile(filepath.Join(dir, "metadata.json"))
		containerMust(t, e)
		var meta containerFixture
		containerMust(t, json.Unmarshal(raw, &meta))
		raw, e = os.ReadFile(filepath.Join(dir, "recovery-private/writer.json"))
		containerMust(t, e)
		var writer ed25519.PrivateKey
		containerMust(t, json.Unmarshal(raw, &writer))
		owner, e := filekit.ReadOwner(filepath.Join(dir, "recovery-private/owner.json"))
		containerMust(t, e)
		source, e := filekit.OpenStore(filepath.Join(dir, "source-store"), owner, false)
		containerMust(t, e)
		// The runner mounts this fixture's data at its final container path. This
		// stage runs only after explicit image initialization and policy admission.
		if meta.Replica != filepath.Join(worker.DomainDirectory("/var/lib/outpost/worker", meta.Trust), "replica") {
			t.Fatal("unexpected replica destination")
		}
		containerMust(t, os.MkdirAll(meta.Replica, 0700))
		replica, e := generation.Open(meta.Replica, meta.Trust, true)
		containerMust(t, e)
		id, e := generation.Seal(context.Background(), source, []string{meta.Version}, replica, generation.Catalog{Format: generation.Format, Domain: meta.Trust.Domain, Repository: meta.Trust.Repository, Epoch: 1, Sequence: 1, SnapshotUnix: time.Now().Unix(), Policy: 1, KitFormat: generation.KitFormat}, writer)
		containerMust(t, e)
		containerMust(t, replica.Close())
		containerMust(t, source.Close())
		containerJSON(t, filepath.Join(dir, "seed-receipt.json"), map[string]string{"generation": id, "version": meta.Version, "sha256": meta.Digest})
		// Only the fresh fixture's encrypted source cache is removed. The standalone
		// kit and materialized keyless replica remain for independent reader checks.
		containerMust(t, os.RemoveAll(filepath.Join(dir, "source-store")))
		return
	}
	containerMust(t, os.Mkdir(dir, 0700))
	for _, name := range []string{"private", "recovery-private", "data", "restored"} {
		containerMust(t, os.Mkdir(filepath.Join(dir, name), 0700))
	}
	owner, e := filekit.NewOwner()
	containerMust(t, e)
	containerMust(t, filekit.WriteOwner(filepath.Join(dir, "recovery-private/owner.json"), owner))
	source, e := filekit.OpenStore(filepath.Join(dir, "source-store"), owner, true)
	containerMust(t, e)
	payload := bytes.Repeat([]byte("synthetic isolated container recovery\n"), 512)
	input := filepath.Join(dir, "sample.input")
	containerMust(t, os.WriteFile(input, payload, 0600))
	version, e := source.Backup(context.Background(), input, filekit.BackupOptions{Names: []string{"sample.txt"}})
	containerMust(t, e)
	containerMust(t, source.Export(context.Background(), version.Version, filepath.Join(dir, "standalone-kit")))
	containerMust(t, source.Close())
	containerMust(t, os.Remove(input))
	ownerPub, ownerKey := containerKey(t)
	nodePub, nodeKey := containerKey(t)
	caPub, caKey := containerKey(t)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic container fixture CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	containerMust(t, e)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, nodePub, caKey)
	containerMust(t, e)
	keyDER, e := x509.MarshalPKCS8PrivateKey(nodeKey)
	containerMust(t, e)
	for name, data := range map[string][]byte{"ca.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "node.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), "node.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})} {
		containerMust(t, writeNew(filepath.Join(dir, "private", name), data))
	}
	parsedLeaf, e := x509.ParseCertificate(leafDER)
	containerMust(t, e)
	node := peer.Identity(parsedLeaf)
	writerPub, writer := containerKey(t)
	maintenance, _ := containerKey(t)
	planner, _ := containerKey(t)
	trust := generation.Trust{Domain: owner.Domain, Repository: storage.Hash([]byte("synthetic packaged replica")), Epoch: 1, Writer: writerPub, Maintenance: maintenance}
	containerJSON(t, filepath.Join(dir, "recovery-private/writer.json"), writer)
	containerJSON(t, filepath.Join(dir, "recovery-private/trust.json"), trust)
	b := worker.Bootstrap{Format: worker.BootstrapFormat, Directory: "/var/lib/outpost/worker", Node: node, Owner: ownerPub, CertificateFile: "/run/outpost/node.crt", PrivateKeyFile: "/run/outpost/node.key", CAFile: "/run/outpost/ca.crt", Credentials: map[string]string{}}
	containerJSON(t, filepath.Join(dir, "private/bootstrap-template.json"), b)
	cfg := control.Config{Format: control.Format, Node: node, Revision: 1, NotBefore: time.Now().Add(-time.Minute).Unix(), ExpiresUnix: time.Now().Add(time.Hour).Unix(), Nodes: []policy.Node{{ID: node, Class: "trusted"}}, Domains: []control.Domain{{Trust: trust, Planner: planner, Placement: policy.Placement{Domain: trust.Domain, AllowedClasses: []string{"trusted"}, Holders: []string{node}}}}, Limits: control.Limits{Parallel: 1, AttemptMillis: 1000, PollSeconds: 1, CapacityBytes: 128 << 20, ReserveBytes: 16 << 20, SpoolBytes: 16 << 20, TelemetryBytes: 1 << 20}}
	for _, revision := range []uint64{1, 2} {
		cfg.Revision = revision
		raw, e := control.Sign(cfg, ownerKey)
		containerMust(t, e)
		name := "policy.json"
		if revision == 2 {
			name = "policy-next.json"
		}
		containerMust(t, writeNew(filepath.Join(dir, "private", name), raw))
	}
	sum := sha256.Sum256(payload)
	containerJSON(t, filepath.Join(dir, "metadata.json"), containerFixture{Node: node, Version: version.Version, Digest: hex.EncodeToString(sum[:]), Bytes: len(payload), Trust: trust, Replica: filepath.Join(worker.DomainDirectory(b.Directory, trust), "replica")})
}
