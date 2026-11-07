package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/teststore"
)

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func id(v string) string { return storage.Hash([]byte(v)) }

type fixture struct {
	r           *Registry
	options     Options
	owner, node ed25519.PrivateKey
	p           Principal
	e           Enrollment
	dir         string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	_, service, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	node, nkey, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	dir := filepath.Join(teststore.Root(t), "registry")
	o := Options{Directory: dir, Owner: pub, Signer: service, Initialize: true}
	r, e := Open(o)
	must(t, e)
	o.Initialize = false
	now := time.Now().Unix()
	f := &fixture{r: r, options: o, owner: key, node: nkey, dir: dir, p: Principal{Actor: id("owner"), Roles: []string{"owner"}, Scopes: []Scope{{id("tenant"), id("domain")}, {id("tenant"), id("second-domain")}}}, e: Enrollment{Format: EnrollmentFormat, Tenant: id("tenant"), Node: identity(node), PublicKey: node, Class: "trusted", Revision: 1, NotBefore: now - 300, ExpiresUnix: now + 3600, Domains: []DomainAdmission{{id("domain"), id("repository"), 1}}}}
	t.Cleanup(func() {
		if f.r != nil {
			f.r.Close()
		}
	})
	return f
}
func (f *fixture) enroll(t *testing.T) {
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	_, e = f.r.ApplyEnrollment(context.Background(), f.p, id("enroll"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
}
func (f *fixture) reopen(t *testing.T) {
	must(t, f.r.Close())
	r, e := Open(f.options)
	must(t, e)
	f.r = r
}
func (f *fixture) report(t *testing.T, sequence uint64, observed int64) []byte {
	logical := int64(4096)
	r := Report{Format: ReportFormat, Node: f.e.Node, Tenant: f.e.Tenant, Domain: id("domain"), EnrollmentRevision: f.e.Revision, Sequence: sequence, ConfigurationRevision: 1, ObservedUnix: observed, Generations: []Generation{{Generation: id("generation"), Sequence: 1, CreatedUnix: observed - 60, Status: "COMPLETE", Target: f.e.Node, Verification: "CIPHERTEXT", VerifiedUnix: observed - 30, LogicalBytes: &logical, Objects: 1, Pinned: true}}, Jobs: []Job{}, Space: Space{State: "UNKNOWN"}}
	raw, e := SignReport(r, f.e, f.node, time.Now())
	must(t, e)
	return raw
}
func TestManagementEnrollmentDurableIntentIdentityScopeAndFences(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	f.r.Fault = func(p string) error {
		if p == "management-enrollment-intent-durable" {
			return errors.New("lost process")
		}
		return nil
	}
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("first"), "INITIAL_ENROLLMENT", raw, 0)
	if e == nil {
		t.Fatal("fault absent")
	}
	if _, e = f.r.Enrollment(ctx, f.p, f.e.Tenant, f.e.Node); !errors.Is(e, ErrUnavailable) {
		t.Fatal("uncommitted enrollment exposed", e)
	}
	f.reopen(t)
	first, e := f.r.ApplyEnrollment(ctx, f.p, id("first"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	again, e := f.r.ApplyEnrollment(ctx, f.p, id("first"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	if first != again {
		t.Fatal("duplicate operation changed receipt")
	}
	viewer := f.p
	viewer.Roles = []string{"viewer"}
	if _, e = f.r.ApplyEnrollment(ctx, viewer, id("forbidden"), "POLICY_CHANGE", raw, 1); !errors.Is(e, ErrDenied) {
		t.Fatal("viewer enrolled", e)
	}
	f.e.Revision++
	f.e.Domains = []DomainAdmission{{id("second-domain"), id("repository-two"), 1}}
	next, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	if _, e = f.r.ApplyEnrollment(ctx, f.p, id("first"), "POLICY_CHANGE", next, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("operation rebound", e)
	}
	if _, e = f.r.ApplyEnrollment(ctx, f.p, id("stale"), "POLICY_CHANGE", next, 0); !errors.Is(e, ErrConflict) {
		t.Fatal("stale revision accepted", e)
	}
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("second"), "POLICY_CHANGE", next, 1)
	must(t, e)
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	must(t, e)
	foreign := f.e
	foreign.Node = identity(pub)
	foreign.PublicKey = pub
	foreign.Tenant = id("other-tenant")
	foreign.Revision = 1
	foreign.Domains = []DomainAdmission{{id("domain"), id("repository"), 1}}
	foreignRaw, e := SignEnrollment(foreign, f.owner)
	must(t, e)
	p := Principal{Actor: id("other-owner"), Roles: []string{"owner"}, Scopes: []Scope{{foreign.Tenant, id("domain")}}}
	if _, e = f.r.ApplyEnrollment(ctx, p, id("cross-domain"), "INITIAL_ENROLLMENT", foreignRaw, 0); !errors.Is(e, ErrConflict) {
		t.Fatal("removed domain lost tenant fence", e)
	}
	if _, e = f.r.Enrollment(ctx, p, foreign.Tenant, f.e.Node); !errors.Is(e, ErrUnavailable) {
		t.Fatal("foreign enrollment disclosed", e)
	}
	audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 256)
	must(t, e)
	if len(audit) != 2 || audit[0].State != "COMPLETE" || audit[1].Operation != id("second") {
		t.Fatal("audit duplicated or absent", audit)
	}
}
func TestManagementReportsKeepOriginalAgeBoundedSlotsAndLastGood(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	now := time.Now().Unix()
	raw := f.report(t, 1, now-60)
	receipt, e := f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, e)
	again, e := f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, raw)
	must(t, e)
	if receipt != again {
		t.Fatal("report replay refreshed receipt")
	}
	view, e := f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), 5*time.Second)
	must(t, e)
	if view.State != "STALE" || view.ObservedUnix != now-60 || view.Space.FreeBytes != nil {
		t.Fatal("stale or unknown shown as current/zero", view)
	}
	changed := f.report(t, 1, now-50)
	if _, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, changed); !errors.Is(e, ErrConflict) {
		t.Fatal("same sequence changed", e)
	}
	if _, e = f.r.PublishReport(ctx, id("other-node"), f.e.Tenant, f.e.Node, raw); !errors.Is(e, ErrDenied) {
		t.Fatal("other node published", e)
	}
	for n := uint64(2); n <= 10; n++ {
		raw = f.report(t, n, now)
		_, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, raw)
		must(t, e)
	}
	files, e := os.ReadDir(f.dir)
	must(t, e)
	count := 0
	for _, entry := range files {
		if strings.HasPrefix(entry.Name(), "report-") {
			count++
		}
	}
	if count != 2 {
		t.Fatal("unbounded report slots", count)
	}
	f.reopen(t)
	view, e = f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), 5*time.Second)
	must(t, e)
	if view.Sequence != 10 || view.ObservedUnix != now {
		t.Fatal("restart lost report")
	}
	f.r.store.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	if _, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, f.report(t, 11, now)); !errors.Is(e, statefile.ErrCapacity) {
		t.Fatal("quota ignored", e)
	}
	f.r.store.Admit = nil
	view, e = f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), 5*time.Second)
	must(t, e)
	if view.Sequence != 10 {
		t.Fatal("failed write removed last observation")
	}
	f.e.Revision++
	f.e.Revoked = true
	revoked, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("revoke"), "REVOKE", revoked, 1)
	must(t, e)
	if _, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, f.report(t, 11, now)); !errors.Is(e, ErrDenied) {
		t.Fatal("revoked node published", e)
	}
	view, e = f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), time.Hour)
	must(t, e)
	if view.State != "STALE" || view.Sequence != 10 {
		t.Fatal("revocation discarded or refreshed last report")
	}
}
func TestManagementRejectsTamperingFutureClockAndUnknownState(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	raw := f.report(t, 1, time.Now().Unix())
	corrupt := bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":2`), 1)
	if _, e := f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, corrupt); e == nil {
		t.Fatal("tampered signature accepted")
	}
	var report Report
	must(t, json.Unmarshal(raw, &report))
	report.ObservedUnix = time.Now().Unix() + 100
	if _, e := SignReport(report, f.e, f.node, time.Now()); e == nil {
		t.Fatal("future observation signed")
	}
	report.ObservedUnix = time.Now().Unix()
	report.Jobs = []Job{{Operation: id("job"), Domain: id("foreign-domain"), Generation: id("generation"), Kind: "PEER", Phase: "RUNNING", UpdatedUnix: report.ObservedUnix}}
	if _, e := SignReport(report, f.e, f.node, time.Now()); e == nil {
		t.Fatal("foreign job admitted")
	}
	must(t, f.r.store.Write("registry.json", []byte("{}")))
	if _, e := f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), time.Hour); !errors.Is(e, ErrInvalid) {
		t.Fatal("unknown state accepted", e)
	}
	kept, e := f.r.store.Read("registry.json")
	must(t, e)
	if string(kept) != "{}" {
		t.Fatal("unknown state reset")
	}
}

type crashInput struct {
	Directory     string
	Owner         ed25519.PublicKey
	Signer        ed25519.PrivateKey
	Principal     Principal
	Enrollment    []byte
	Report        []byte
	Point         string
	Configuration *SignedMutation
}

func TestManagementSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_MANAGEMENT_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var input crashInput
	must(t, json.Unmarshal(raw, &input))
	r, e := Open(Options{Directory: input.Directory, Owner: input.Owner, Signer: input.Signer})
	must(t, e)
	defer r.Close()
	r.Fault = func(p string) error {
		if p == input.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	if input.Configuration != nil {
		enrollment, e := VerifyEnrollment(input.Enrollment, input.Owner)
		must(t, e)
		_, e = r.ApplyConfiguration(context.Background(), input.Principal, enrollment.Tenant, enrollment.Node, *input.Configuration)
		must(t, e)
	} else if len(input.Report) > 0 {
		enrollment, e := VerifyEnrollment(input.Enrollment, input.Owner)
		must(t, e)
		_, e = r.PublishReport(context.Background(), enrollment.Node, enrollment.Tenant, enrollment.Node, input.Report)
		must(t, e)
	} else {
		_, e = r.ApplyEnrollment(context.Background(), input.Principal, id("child-enroll"), "INITIAL_ENROLLMENT", input.Enrollment, 0)
		must(t, e)
	}
	t.Fatal("kill point absent")
}
func TestManagementSIGKILLRetainsEnrollmentAndReportCommitBoundaries(t *testing.T) {
	for _, point := range []string{"management-enrollment-intent-durable", "management-enrollment-result-durable", "management-report-slot-durable", "management-report-pointer-durable", "management-config-intent-durable", "management-config-cache-durable", "management-config-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			enrollment, e := SignEnrollment(f.e, f.owner)
			must(t, e)
			input := crashInput{Directory: f.dir, Owner: f.options.Owner, Signer: f.options.Signer, Principal: f.p, Enrollment: enrollment, Point: point}
			if strings.Contains(point, "report") {
				f.enroll(t)
				_, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, f.report(t, 1, time.Now().Unix()-10))
				must(t, e)
				input.Report = f.report(t, 2, time.Now().Unix())
			}
			if strings.Contains(point, "config") {
				f.enroll(t)
				cfg := configFixture(t, f)
				mutation := configurationMutation(t, f, cfg, "child-config", 0)
				preview, e := f.r.PreviewConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, mutation)
				must(t, e)
				mutation.PreviewDigest = preview.CandidateDigest
				input.Configuration = &mutation
			}
			must(t, f.r.Close())
			f.r = nil
			raw, e := json.Marshal(input)
			must(t, e)
			file := filepath.Join(filepath.Dir(f.dir), "child.json")
			must(t, os.WriteFile(file, raw, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementSIGKILLChild$")
			cmd.Env = append(os.Environ(), "OUTPOST_MANAGEMENT_KILL="+file)
			output, e := cmd.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child did not terminate: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("wrong signal: %v %s", e, output)
			}
			f.r, e = Open(f.options)
			must(t, e)
			if input.Configuration != nil {
				_, e = f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
				if point != "management-config-result-durable" && e == nil {
					t.Fatal("unfinished configuration published")
				}
				receipt, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, *input.Configuration)
				must(t, e)
				if receipt.State != "COMPLETE" {
					t.Fatal(receipt)
				}
				cfg, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
				must(t, e)
				if !bytes.Equal(cfg.Document, input.Configuration.Document) {
					t.Fatal("configuration differs after SIGKILL")
				}
			} else if len(input.Report) > 0 {
				view, e := f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), time.Hour)
				must(t, e)
				want := uint64(1)
				if point == "management-report-pointer-durable" {
					want = 2
				}
				if view.Sequence != want {
					t.Fatal("wrong commit boundary", view.Sequence, want)
				}
				_, e = f.r.PublishReport(ctx, f.e.Node, f.e.Tenant, f.e.Node, input.Report)
				must(t, e)
				view, e = f.r.Report(ctx, f.p, f.e.Tenant, f.e.Node, id("domain"), time.Hour)
				must(t, e)
				if view.Sequence != 2 {
					t.Fatal("report retry did not converge")
				}
			} else {
				receipt, e := f.r.ApplyEnrollment(ctx, f.p, id("child-enroll"), "INITIAL_ENROLLMENT", enrollment, 0)
				must(t, e)
				if receipt.State != "COMPLETE" {
					t.Fatal(receipt)
				}
				audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 256)
				must(t, e)
				if len(audit) != 1 {
					t.Fatal("duplicate audit")
				}
			}
		})
	}
}
