package sourceagent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/observation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// Optional artifact check: the caller supplies a previously verified executable
// and its digest. Ordinary unit runs do not fetch or execute external artifacts.
func TestSourceRenewalCLIPreviousReaderRefusesMigratedState(t *testing.T) {
	current := os.Getenv("OUTPOST_SOURCE_CURRENT_CLI")
	previous := os.Getenv("OUTPOST_SOURCE_PREVIOUS_CLI")
	if current == "" && previous == "" {
		t.Skip("current and previous CLI artifacts not supplied")
	}
	expected := os.Getenv("OUTPOST_SOURCE_PREVIOUS_SHA256")
	if !filepath.IsAbs(current) || !filepath.IsAbs(previous) || !storage.ID(expected) {
		t.Fatal("incomplete CLI artifact configuration")
	}
	input, e := os.Open(previous)
	must(t, e)
	raw, e := io.ReadAll(io.LimitReader(input, (64<<20)+1))
	must(t, e)
	must(t, input.Close())
	if len(raw) > 64<<20 || storage.Hash(raw) != expected {
		t.Fatal("previous executable digest mismatch")
	}
	// Runtime data remains on the test volume. Only the verified executable is
	// copied into this isolated container's executable temporary filesystem.
	file, e := os.CreateTemp("/tmp", "outpost-previous-*")
	must(t, e)
	oldCLI := file.Name()
	t.Cleanup(func() { os.Remove(oldCLI) })
	_, e = file.Write(raw)
	must(t, e)
	must(t, file.Chmod(0700))
	must(t, file.Close())
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	head, e := f.a.Status(ctx)
	must(t, e)
	bootstrap, e := json.Marshal(f.b)
	must(t, e)
	path := filepath.Join(f.base, "source bootstrap.json")
	must(t, os.WriteFile(path, bootstrap, 0600))
	authorityPath := filepath.Join(f.base, "renewed authority.json")
	must(t, os.WriteFile(authorityPath, renewedAuthority(t, f, 2), 0600))
	run := func(binary, command string, extra ...string) ([]byte, error) {
		t.Helper()
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		args := append([]string{command, "--bootstrap", path}, extra...)
		output, err := exec.CommandContext(bounded, binary, args...).CombinedOutput()
		if bounded.Err() != nil {
			t.Fatal("CLI exceeded deadline", command)
		}
		return output, err
	}
	before, e := f.a.store.Read("agent.json")
	must(t, e)
	output, e := run(oldCLI, "source-status")
	if e != nil || !bytes.Contains(output, []byte(Format)) {
		t.Fatal("previous executable cannot read original state", e, string(output))
	}
	output, e = run(current, "source-renew", "--input", authorityPath)
	if e != nil {
		t.Fatal("current CLI renewal failed", e, string(output))
	}
	var renewed struct {
		Result Renewal `json:"result"`
	}
	must(t, json.Unmarshal(output, &renewed))
	renewal := renewed.Result
	if renewal.Format != renewedFormat || renewal.Revision != 2 || renewal.Sequence != head.Sequence || renewal.Generation != head.Generation || renewal.LegacyDigest != storage.Hash(before) {
		t.Fatal("migration lost history", renewal)
	}
	migrated, e := f.a.store.Read("agent.json")
	must(t, e)
	for _, command := range []string{"source-status", "source-next", "source-run", "source-init"} {
		_, e = run(oldCLI, command)
		var exit *exec.ExitError
		if !errors.As(e, &exit) || exit.ExitCode() == 0 {
			t.Fatal("old executable accepted migrated state", command, e)
		}
		after, e := f.a.store.Read("agent.json")
		must(t, e)
		if !bytes.Equal(after, migrated) {
			t.Fatal("old executable changed active state", command)
		}
	}
	output, e = run(current, "source-status")
	if e != nil {
		t.Fatal(e, string(output))
	}
	var response struct {
		Result Status `json:"result"`
	}
	must(t, json.Unmarshal(output, &response))
	status := response.Result
	if status.Format != renewedFormat || status.AuthorityRevision != 2 || status.Generation != head.Generation {
		t.Fatal(status)
	}
	if _, e = run(current, "source-renew", "--input", f.b.AuthorityFile); e == nil {
		t.Fatal("CLI accepted previous authority")
	}
	anchors, e := os.ReadFile(f.b.AuthorityFile)
	must(t, e)
	if !bytes.Equal(anchors, f.authority) {
		t.Fatal("renewal overwrote installation anchor")
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
}

func renewedAuthority(t *testing.T, f *fixture, revision uint64) []byte {
	t.Helper()
	g := f.grant
	g.Revision = revision
	g.ExpiresUnix += 600
	raw, e := ingress.SignAuthority(g, f.ownerSigner)
	must(t, e)
	return raw
}
func TestSourceRenewalRevalidatesAfterLeaseWait(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before, e := f.a.store.Read("agent.json")
	must(t, e)
	g := f.grant
	g.Revision = 2
	g.ExpiresUnix = time.Now().Unix() + 2
	authority, e := ingress.SignAuthority(g, f.ownerSigner)
	must(t, e)
	locked, release, stopped := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		stopped <- f.a.lease.WithLock(ctx, func() error {
			close(locked)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	<-locked
	result := make(chan error, 1)
	go func() { _, e := f.a.Renew(ctx, authority, nil); result <- e }()
	select {
	case e := <-result:
		close(release)
		<-stopped
		t.Fatal("renewal did not wait for capture lease", e)
	case <-time.After(30 * time.Millisecond):
	}
	<-time.After(time.Until(time.Unix(g.ExpiresUnix, 0).Add(20 * time.Millisecond)))
	close(release)
	must(t, <-stopped)
	if e = <-result; e == nil || ctx.Err() != nil {
		t.Fatal("expired renewal admitted after lease wait", e)
	}
	after, e := f.a.store.Read("agent.json")
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("expired renewal changed source journal")
	}
}
func TestSourceRenewalPreservesHeadScheduleAndIndependentVersions(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.ConfigureSchedule(ctx, testSchedule()))
	must(t, f.a.scheduleStep(ctx))
	first, e := f.a.Status(ctx)
	must(t, e)
	schedule, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	content, e := os.ReadFile(filepath.Join(f.tree, "private.bin"))
	must(t, e)
	before, e := f.a.store.Read("agent.json")
	must(t, e)
	raw := renewedAuthority(t, f, 2)
	result, e := f.a.Renew(ctx, raw, nil)
	must(t, e)
	if result.Sequence != 1 || result.Generation != first.Generation || result.LegacyDigest != storage.Hash(before) {
		t.Fatal(result)
	}
	if e = f.a.Next(ctx); !errors.Is(e, ErrAuthorityChanged) {
		t.Fatal("old open instance reused old scope", e)
	}
	f.reopen(t)
	after, e := f.a.Status(ctx)
	must(t, e)
	if after.Sequence != first.Sequence || after.Generation != first.Generation || after.AuthorityRevision != 2 || after.Format != renewedFormat {
		t.Fatal(after)
	}
	recovered, e := f.a.store.Read("agent-v1-" + result.LegacyDigest + ".json")
	must(t, e)
	if !bytes.Equal(recovered, before) {
		t.Fatal("old signed state changed")
	}
	same, e := f.a.ScheduleStatus(ctx)
	must(t, e)
	left, _ := json.Marshal(schedule)
	right, _ := json.Marshal(same)
	if !bytes.Equal(left, right) {
		t.Fatal("renewal reset scheduling progress")
	}
	_, e = f.a.Renew(ctx, raw, nil)
	must(t, e)
	if _, e = f.a.Renew(ctx, f.authority, nil); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("old owner grant replay", e)
	}
	// A separately admitted new receiver registry preserves the replica's head.
	replica, e := generation.Open(f.replicaPath, f.grant.Trust, false)
	must(t, e)
	defer replica.Close()
	registry, e := ingress.OpenRegistry(ctx, ingress.RegistryOptions{Directory: filepath.Join(f.base, "registry-revision-two"), Authority: raw, Owner: f.b.Local.Owner, Replica: replica, Certificate: f.destination, Roots: f.roots, Limits: peer.Limits{Concurrency: 1, Timeout: 5 * time.Second, Attempts: 1}, Initialize: true})
	must(t, e)
	defer registry.Close()
	f.intercept = func(w http.ResponseWriter, r *http.Request) bool { registry.ServeHTTP(w, r); return true }
	next := bytes.Repeat([]byte("renewed source"), 24000)
	must(t, os.WriteFile(filepath.Join(f.tree, "private.bin"), next, 0640))
	must(t, f.a.Next(ctx))
	must(t, f.a.Run(ctx))
	second, e := f.a.Status(ctx)
	must(t, e)
	if second.Sequence != 2 || second.Generation == first.Generation {
		t.Fatal(second)
	}
	must(t, os.RemoveAll(f.tree)) // Only this synthetic source; never production cleanup.
	for name, item := range map[string]struct {
		id      string
		content []byte
	}{"old": {first.Generation, content}, "new": {second.Generation, next}} {
		out := filepath.Join(f.base, "renewal-restore-"+name)
		_, e = generation.RecoverMaterialized(ctx, f.replicaPath, item.id, f.grant.Trust, f.owner, generation.RecoverySelection{}, out)
		must(t, e)
		got, e := os.ReadFile(filepath.Join(out, "private.bin"))
		must(t, e)
		if !bytes.Equal(got, item.content) {
			t.Fatal("independent version mismatch", name)
		}
	}
	f.reopen(t)
	must(t, f.a.Run(ctx))
}
func TestSourceRenewalRejectsPendingExpansionAndDamagedCheckpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	raw := renewedAuthority(t, f, 2)
	must(t, f.a.Next(ctx))
	before, e := f.a.store.Read("agent.json")
	must(t, e)
	if _, e = f.a.Renew(ctx, raw, nil); !errors.Is(e, ingress.ErrConflict) {
		t.Fatal("pending intent replaced", e)
	}
	after, _ := f.a.store.Read("agent.json")
	if !bytes.Equal(before, after) {
		t.Fatal("pending state changed")
	}
	must(t, f.a.Run(ctx))
	bad := f.grant
	bad.Revision = 2
	bad.MaxBytes++
	expanded, e := ingress.SignAuthority(bad, f.ownerSigner)
	must(t, e)
	if _, e = f.a.Renew(ctx, expanded, nil); !errors.Is(e, ingress.ErrDenied) {
		t.Fatal("renewal expanded scope", e)
	}
	result, e := f.a.Renew(ctx, raw, nil)
	must(t, e)
	f.reopen(t)
	path := filepath.Join(f.b.Local.Directory, "state", "agent-v1-"+result.LegacyDigest+".json")
	old, e := os.ReadFile(path)
	must(t, e)
	must(t, os.WriteFile(path, append(old, ' '), 0600))
	if _, e = f.a.Status(ctx); !errors.Is(e, ErrInvalid) {
		t.Fatal("damaged migration checkpoint accepted", e)
	}
}
func TestSourceRenewalObservationEpochCannotReplay(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	must(t, f.a.Close())
	f.a = nil
	certificate, e := x509.ParseCertificate(f.replicaCertificate.Certificate[0])
	must(t, e)
	leaf := peer.Identity(certificate)
	grant := observation.Grant{Format: observation.GrantFormat, Trust: f.grant.Trust, Reader: f.grant.Source, Collector: f.grant.Ingress, Targets: []string{leaf}, Epoch: 1, NotBefore: f.grant.NotBefore, ExpiresUnix: f.grant.ExpiresUnix, MaxAgeSeconds: 3600}
	initial, e := observation.SignGrant(grant, f.ownerSigner)
	must(t, e)
	f.b.ObservationFile = filepath.Join(f.base, "observation-initial.json")
	must(t, os.WriteFile(f.b.ObservationFile, initial, 0600))
	f.b.Profile.MinimumCopies = 2
	f.b.Profile.CopyTargets = append(f.b.Profile.CopyTargets, leaf)
	f.b.Local.Directory = filepath.Join(filepath.Dir(f.b.Local.Directory), "two-copy-agent")
	f.a, e = Open(ctx, f.b, true)
	must(t, e)
	grant.Epoch = 2
	grant.ExpiresUnix += 600
	renewed, e := observation.SignGrant(grant, f.ownerSigner)
	must(t, e)
	_, e = f.a.Renew(ctx, renewedAuthority(t, f, 2), renewed)
	must(t, e)
	f.reopen(t)
	if !bytes.Equal(f.a.observation, renewed) {
		t.Fatal("observation grant not persisted")
	}
	if _, e = f.a.Renew(ctx, renewedAuthority(t, f, 3), initial); !errors.Is(e, observation.ErrDenied) {
		t.Fatal("observation epoch replay", e)
	}
}
func TestSourceRenewalSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_SOURCE_RENEWAL_KILL")
	if file == "" {
		t.Skip("child only")
	}
	var in struct {
		Bootstrap Bootstrap
		Authority []byte
		Point     string
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	must(t, json.Unmarshal(raw, &in))
	a, e := Open(context.Background(), in.Bootstrap, false)
	must(t, e)
	defer a.Close()
	a.Fault = func(point string) error {
		if point == in.Point {
			syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_, e = a.Renew(context.Background(), in.Authority, nil)
	must(t, e)
	t.Fatal("kill not reached")
}
func TestSourceRenewalSIGKILLPreservesOldOrNewAuthority(t *testing.T) {
	for _, point := range []string{"source-renewal-checkpoint-durable", "source-renewal-committed"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			must(t, f.a.ConfigureSchedule(ctx, testSchedule()))
			authority := renewedAuthority(t, f, 2)
			must(t, f.a.Close())
			f.a = nil
			raw, e := json.Marshal(struct {
				Bootstrap Bootstrap
				Authority []byte
				Point     string
			}{f.b, authority, point})
			must(t, e)
			file := filepath.Join(f.base, "renewal-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestSourceRenewalSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_SOURCE_RENEWAL_KILL="+file)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatal(e, string(output))
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal(e, string(output))
			}
			f.a, e = Open(ctx, f.b, false)
			must(t, e)
			if point == "source-renewal-committed" && f.a.grant.Revision != 2 || point != "source-renewal-committed" && f.a.grant.Revision != 1 {
				t.Fatal("mixed authority", f.a.grant.Revision)
			}
			_, e = f.a.Renew(ctx, authority, nil)
			must(t, e)
			f.reopen(t)
			s, e := f.a.Status(ctx)
			must(t, e)
			if s.Sequence != 0 || s.AuthorityRevision != 2 {
				t.Fatal(s)
			}
			_, e = f.a.ScheduleStatus(ctx)
			must(t, e)
		})
	}
}
