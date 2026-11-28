package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func interruptAt(point string) func(string) error {
	return func(p string) error {
		if p == point {
			return errors.New("interrupted fixture")
		}
		return nil
	}
}
func checkReconcile(t *testing.T, r ReconcileResult, state string) {
	t.Helper()
	if r.Format != "outpost-management-reconcile-1" || r.ObservedUnix < 1 || len(r.Items) != 1 || r.Items[0].State != state {
		t.Fatalf("unexpected reconcile %+v", r)
	}
}

func TestManagementReconcileEnrollmentCurrentACLQuotaAndOriginalReceipt(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("reconcile-enrollment"), "INITIAL_ENROLLMENT", raw, 0)
	if e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	before, e := os.ReadFile(filepath.Join(f.dir, "registry.json"))
	must(t, e)
	view := f.p
	view.Roles = []string{"viewer"}
	for _, acl := range [][]Principal{nil, {view}} {
		v, e := f.r.Reconcile(ctx, acl, 0, 8)
		must(t, e)
		checkReconcile(t, v, "BLOCKED")
		if v.Items[0].ErrorCode != "AUTHORIZATION_UNAVAILABLE" {
			t.Fatal(v)
		}
	}
	after, e := os.ReadFile(filepath.Join(f.dir, "registry.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("denied reconciliation changed state")
	}
	f.r.store.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
	v, e := f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	checkReconcile(t, v, "BLOCKED")
	if v.Items[0].ErrorCode != "CAPACITY" {
		t.Fatal(v)
	}
	f.r.store.Admit = nil
	v, e = f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	checkReconcile(t, v, "COMPLETE")
	receipt, e := f.r.ApplyEnrollment(ctx, f.p, id("reconcile-enrollment"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	f.reopen(t)
	v, e = f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	if len(v.Items) != 0 {
		t.Fatal("historical operation replayed", v)
	}
	same, e := f.r.ApplyEnrollment(ctx, f.p, receipt.Operation, "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	if same != receipt {
		t.Fatal("original result changed")
	}
}

func TestManagementReconcileConfigurationDistinguishesAppliedEffectFromNewAuthority(t *testing.T) {
	for _, point := range []string{"management-config-intent-durable", "management-config-cache-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			f.enroll(t)
			cfg := configFixture(t, f)
			input := configurationMutation(t, f, cfg, "pending-config", 0)
			input.PreviewDigest = storage.Hash(input.Document)
			f.r.Fault = interruptAt(point)
			_, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
			if e == nil {
				t.Fatal("missing interruption")
			}
			f.reopen(t)
			v, e := f.r.Reconcile(ctx, nil, 0, 8)
			must(t, e)
			if point == "management-config-intent-durable" {
				checkReconcile(t, v, "BLOCKED")
				cache, e := f.r.cacheRaw(ctx, f.e.Node)
				must(t, e)
				if len(cache) != 0 {
					t.Fatal("revoked actor applied config")
				}
				v, e = f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
				must(t, e)
			}
			checkReconcile(t, v, "COMPLETE")
			current, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
			must(t, e)
			if !bytes.Equal(current.Document, input.Document) {
				t.Fatal("candidate changed")
			}
			receipt, e := f.r.Operation(ctx, f.p, f.e.Tenant, input.Operation)
			must(t, e)
			f.reopen(t)
			v, e = f.r.Reconcile(ctx, nil, 0, 8)
			must(t, e)
			if len(v.Items) != 0 {
				t.Fatal(v)
			}
			same, e := f.r.Operation(ctx, f.p, f.e.Tenant, input.Operation)
			must(t, e)
			if same != receipt {
				t.Fatal("receipt time refreshed")
			}
		})
	}
}

func TestManagementReconcileCommandPagingNeverClaimsExecution(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, req, node := commandFixture(t, f)
	f.r.Fault = interruptAt("management-command-intent-durable")
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	if e == nil {
		t.Fatal("missing interruption")
	}
	second := req
	second.Operation = id("second-command")
	second.Kind = "resume"
	other := f.p
	other.Actor = id("other-owner")
	_, e = f.r.AdmitCommand(ctx, other, f.e.Tenant, f.e.Node, second)
	if e == nil {
		t.Fatal("missing second interruption")
	}
	f.reopen(t)
	first, e := f.r.Reconcile(ctx, []Principal{other}, 0, 1)
	must(t, e)
	checkReconcile(t, first, "BLOCKED")
	if first.NextSequence == 0 {
		t.Fatal("blocked item starves later intent")
	}
	next, e := f.r.Reconcile(ctx, []Principal{other}, first.NextSequence, 1)
	must(t, e)
	checkReconcile(t, next, "PUBLISHED")
	if next.NextSequence != 0 {
		t.Fatal(next)
	}
	secondReceipt, e := f.r.Operation(ctx, other, f.e.Tenant, second.Operation)
	must(t, e)
	if secondReceipt.State != "ADMITTED" || secondReceipt.ResultDigest != "" {
		t.Fatal("publication claimed execution")
	}
	items, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 0 {
		t.Fatal("unresolved first intent overtaken")
	}
	last, e := f.r.Reconcile(ctx, []Principal{f.p, other}, 0, 8)
	must(t, e)
	checkReconcile(t, last, "PUBLISHED")
	items, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(items) != 2 {
		t.Fatal("original commands unavailable", len(items))
	}
	ack := commandAck(t, f, items[0].Document)
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, req.Operation, ack)
	must(t, e)
	f.reopen(t)
	done, e := f.r.Reconcile(ctx, []Principal{f.p, other}, 0, 8)
	must(t, e)
	if len(done.Items) != 0 {
		t.Fatal("published/acknowledged command replayed")
	}
}

func TestManagementReconcileRejectsChangedCandidateAndCancelledContext(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.enroll(t)
	cfg := configFixture(t, f)
	input := configurationMutation(t, f, cfg, "candidate", 0)
	input.PreviewDigest = storage.Hash(input.Document)
	f.r.Fault = interruptAt("management-config-cache-durable")
	_, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, input)
	if e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	must(t, os.WriteFile(filepath.Join(f.dir, "blobs", "candidate-"+input.PreviewDigest+".json"), []byte("corrupt"), 0600))
	v, e := f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	checkReconcile(t, v, "BLOCKED")
	if v.Items[0].ErrorCode != "INVALID_STATE" {
		t.Fatal(v)
	}
	if _, e = f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node); e == nil {
		t.Fatal("corrupt candidate bypassed")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = f.r.Reconcile(cancelled, []Principal{f.p}, 0, 8); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, limit := range []int{0, 65} {
		if _, e = f.r.Reconcile(ctx, []Principal{f.p}, 0, limit); e == nil {
			t.Fatal("unbounded page")
		}
	}
}

func TestManagementReconcileAfterActualSIGKILLWithoutClientReplay(t *testing.T) {
	for _, point := range []string{"management-enrollment-intent-durable", "management-config-intent-durable", "management-config-cache-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			raw, e := SignEnrollment(f.e, f.owner)
			must(t, e)
			input := crashInput{Directory: f.dir, Owner: f.options.Owner, Signer: f.options.Signer, Principal: f.p, Enrollment: raw, Point: point}
			if point != "management-enrollment-intent-durable" {
				f.enroll(t)
				c := configFixture(t, f)
				mutation := configurationMutation(t, f, c, "child-config", 0)
				mutation.PreviewDigest = storage.Hash(mutation.Document)
				input.Configuration = &mutation
			}
			must(t, f.r.Close())
			f.r = nil
			data, e := json.Marshal(input)
			must(t, e)
			file := filepath.Join(filepath.Dir(f.dir), "reconcile-child.json")
			must(t, os.WriteFile(file, data, 0600))
			bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			child := exec.CommandContext(bounded, os.Args[0], "-test.run=^TestManagementSIGKILLChild$")
			child.Env = append(os.Environ(), "OUTPOST_MANAGEMENT_KILL="+file)
			output, e := child.CombinedOutput()
			exit, ok := e.(*exec.ExitError)
			if !ok || bounded.Err() != nil {
				t.Fatalf("child: %v %s", e, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not SIGKILL")
			}
			f.r, e = Open(f.options)
			must(t, e)
			v, e := f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
			must(t, e)
			checkReconcile(t, v, "COMPLETE")
			if input.Configuration != nil {
				c, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
				must(t, e)
				if !bytes.Equal(c.Document, input.Configuration.Document) {
					t.Fatal("wrong durable policy")
				}
			} else {
				en, e := f.r.Enrollment(ctx, f.p, f.e.Tenant, f.e.Node)
				must(t, e)
				if en.Node != f.e.Node {
					t.Fatal("wrong enrollment")
				}
			}
		})
	}
}
