package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func resolutionInput(t *testing.T, f *fixture, operation string) ResolveRequest {
	t.Helper()
	receipt, e := f.r.Operation(context.Background(), f.p, f.e.Tenant, operation)
	must(t, e)
	return ResolveRequest{id("resolve-" + operation), receipt.RequestDigest, "ABANDON_UNPUBLISHED"}
}
func pendingEnrollment(t *testing.T, f *fixture) []byte {
	t.Helper()
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	if _, e = f.r.ApplyEnrollment(context.Background(), f.p, id("pending-enroll"), "INITIAL_ENROLLMENT", raw, 0); e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	return raw
}
func TestManagementResolutionEnrollmentAuthorityReplayAuditAndCheckpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	raw := pendingEnrollment(t, f)
	input := resolutionInput(t, f, id("pending-enroll"))
	previous, e := f.r.store.Read("registry.json")
	must(t, e)
	for _, role := range []string{"operator", "viewer", "recovery", "node"} {
		denied := f.p
		denied.Roles = []string{role}
		if _, e = f.r.ResolveUnpublished(ctx, denied, f.e.Tenant, id("pending-enroll"), input); !errors.Is(e, ErrDenied) {
			t.Fatal(role, e)
		}
	}
	foreign := f.p
	foreign.Scopes = []Scope{{f.e.Tenant, id("second-domain")}}
	if _, e = f.r.ResolveUnpublished(ctx, foreign, f.e.Tenant, id("pending-enroll"), input); !errors.Is(e, ErrUnavailable) {
		t.Fatal("partial owner", e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = f.r.ResolveUnpublished(cancelled, f.p, f.e.Tenant, id("pending-enroll"), input); e == nil {
		t.Fatal("cancelled mutation")
	}
	nextOwner := f.p
	nextOwner.Actor = id("replacement-owner")
	preview, e := f.r.ResolutionPreview(ctx, nextOwner, f.e.Tenant, id("pending-enroll"))
	must(t, e)
	if !preview.CanAbandon || preview.TargetDigest != input.TargetDigest {
		t.Fatal(preview)
	}
	receipt, e := f.r.ResolveUnpublished(ctx, nextOwner, f.e.Tenant, id("pending-enroll"), input)
	must(t, e)
	if receipt.State != "COMPLETE" {
		t.Fatal(receipt)
	}
	f.reopen(t)
	same, e := f.r.ResolveUnpublished(ctx, nextOwner, f.e.Tenant, id("pending-enroll"), input)
	must(t, e)
	if same != receipt {
		t.Fatal("resolution refreshed")
	}
	original, e := f.r.ApplyEnrollment(ctx, f.p, id("pending-enroll"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	if original.State != "ABANDONED" {
		t.Fatal(original)
	}
	if _, e = f.r.Enrollment(ctx, f.p, f.e.Tenant, f.e.Node); e == nil {
		t.Fatal("abandoned enrollment published")
	}
	state, e := f.r.load()
	must(t, e)
	if state.Format != resolutionFormat || state.LegacyCheckpoint != storage.Hash(previous) {
		t.Fatal("format fence missing")
	}
	backup, e := f.r.store.Read("registry-v1-" + state.LegacyCheckpoint + ".json")
	must(t, e)
	if !bytes.Equal(previous, backup) {
		t.Fatal("checkpoint changed")
	}
	audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 32)
	must(t, e)
	if len(audit) != 2 || audit[0].Actor != f.p.Actor || audit[0].State != "ADMITTED" || audit[1].Actor != nextOwner.Actor || audit[1].Action != "ABANDON_INTENT" || audit[1].Operation != input.Operation {
		t.Fatal(audit)
	}
	read, e := f.r.Operation(ctx, f.p, f.e.Tenant, input.Operation)
	must(t, e)
	if read != receipt {
		t.Fatal("resolution receipt inaccessible")
	}
	replay := input
	replay.Operation = id("other-resolution")
	if _, e = f.r.ResolveUnpublished(ctx, nextOwner, f.e.Tenant, id("pending-enroll"), replay); !errors.Is(e, ErrConflict) {
		t.Fatal("duplicate resolution rebound", e)
	}
	if _, e = f.r.ApplyEnrollment(ctx, f.p, input.Operation, "INITIAL_ENROLLMENT", raw, 0); !errors.Is(e, ErrConflict) {
		t.Fatal("resolution ID reused", e)
	}
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("fresh-enrollment"), "INITIAL_ENROLLMENT", raw, 0)
	must(t, e)
	result, e := f.r.Reconcile(ctx, []Principal{f.p}, 0, 8)
	must(t, e)
	if len(result.Items) != 0 {
		t.Fatal("abandoned intent reconciled", result)
	}
}
func TestManagementResolutionCommandUnblocksLaterDeliveryWithoutCancellingPublished(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, req, node := commandFixture(t, f)
	f.r.Fault = interruptAt("management-command-envelope-durable")
	if _, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	later := req
	later.Operation = id("later-resume")
	later.Kind = "resume"
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, later)
	must(t, e)
	queue, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(queue) != 0 {
		t.Fatal("overtook pending")
	}
	input := resolutionInput(t, f, req.Operation)
	_, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, req.Operation, input)
	must(t, e)
	queue, _, e = f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
	must(t, e)
	if len(queue) != 1 {
		t.Fatal(queue)
	}
	envelope, _, e := command.VerifyEnvelope(queue[0].Document, f.options.Owner)
	must(t, e)
	if envelope.Request.Operation != later.Operation {
		t.Fatal("abandoned command delivered")
	}
	same, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	if same.State != "ABANDONED" {
		t.Fatal(same)
	}
	preview, e := f.r.ResolutionPreview(ctx, f.p, f.e.Tenant, later.Operation)
	must(t, e)
	if preview.CanAbandon || preview.Reason != "COMMAND_PUBLISHED" {
		t.Fatal(preview)
	}
	if _, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, later.Operation, resolutionInput(t, f, later.Operation)); !errors.Is(e, ErrConflict) {
		t.Fatal("published command cancelled", e)
	}
	ack := commandAck(t, f, queue[0].Document)
	_, e = f.r.AcknowledgeCommand(ctx, node, f.e.Tenant, f.e.Node, later.Operation, ack)
	must(t, e)
	f.reopen(t)
	same, e = f.r.Operation(ctx, f.p, f.e.Tenant, req.Operation)
	must(t, e)
	if same.State != "ABANDONED" {
		t.Fatal(same)
	}
}
func TestManagementResolutionConfigurationDistinguishesDurablePublication(t *testing.T) {
	for _, point := range []string{"management-config-intent-durable", "management-config-cache-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			f.enroll(t)
			cfg := configFixture(t, f)
			original := configurationMutation(t, f, cfg, "initial-policy", 0)
			original.PreviewDigest = storage.Hash(original.Document)
			_, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, original)
			must(t, e)
			cfg.Revision++
			cfg.Limits.Parallel++
			candidate := configurationMutation(t, f, cfg, "pending-policy", 1)
			candidate.PreviewDigest = storage.Hash(candidate.Document)
			f.r.Fault = interruptAt(point)
			if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, candidate); e == nil {
				t.Fatal("missing interruption")
			}
			f.reopen(t)
			preview, e := f.r.ResolutionPreview(ctx, f.p, f.e.Tenant, candidate.Operation)
			must(t, e)
			input := resolutionInput(t, f, candidate.Operation)
			_, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, candidate.Operation, input)
			if point == "management-config-cache-durable" {
				if preview.CanAbandon || !errors.Is(e, ErrConflict) {
					t.Fatal("published policy abandoned", preview, e)
				}
				result, e := f.r.Reconcile(ctx, nil, 0, 8)
				must(t, e)
				checkReconcile(t, result, "COMPLETE")
				return
			}
			must(t, e)
			if !preview.CanAbandon {
				t.Fatal(preview)
			}
			receipt, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, candidate)
			must(t, e)
			if receipt.State != "ABANDONED" {
				t.Fatal(receipt)
			}
			current, e := f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node)
			must(t, e)
			if !bytes.Equal(current.Document, original.Document) {
				t.Fatal("abandoned policy changed cache")
			}
			candidate.Operation = id("replacement-policy")
			_, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, candidate)
			must(t, e)
		})
	}
}
func TestManagementResolutionQuotaPreservesOriginalIntentAndRetry(t *testing.T) {
	for _, failure := range []int{1, 2} {
		t.Run(string(rune('0'+failure)), func(t *testing.T) {
			f := newFixture(t)
			pendingEnrollment(t, f)
			input := resolutionInput(t, f, id("pending-enroll"))
			before, e := f.r.store.Read("registry.json")
			must(t, e)
			writes := 0
			f.r.store.Admit = func(string, int) (func(bool) error, error) {
				writes++
				if writes == failure {
					return nil, statefile.ErrCapacity
				}
				return func(bool) error { return nil }, nil
			}
			_, e = f.r.ResolveUnpublished(context.Background(), f.p, f.e.Tenant, id("pending-enroll"), input)
			if !errors.Is(e, statefile.ErrCapacity) {
				t.Fatal(e)
			}
			after, e := f.r.store.Read("registry.json")
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("failed resolution changed original")
			}
			f.r.store.Admit = nil
			f.reopen(t)
			_, e = f.r.ResolveUnpublished(context.Background(), f.p, f.e.Tenant, id("pending-enroll"), input)
			must(t, e)
		})
	}
}
func TestManagementResolutionRacesPublicationWithoutFalseNoEffectClaim(t *testing.T) {
	for i := 0; i < 4; i++ {
		f := newFixture(t)
		ctx := context.Background()
		_, req, node := commandFixture(t, f)
		f.r.Fault = interruptAt("management-command-intent-durable")
		if _, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req); e == nil {
			t.Fatal("no interruption")
		}
		f.reopen(t)
		input := resolutionInput(t, f, req.Operation)
		var resolution, admission Receipt
		var re, ae error
		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		go func() {
			defer wg.Done()
			<-start
			resolution, re = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, req.Operation, input)
		}()
		go func() {
			defer wg.Done()
			<-start
			admission, ae = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, req)
		}()
		close(start)
		wg.Wait()
		must(t, ae)
		queue, _, e := f.r.Commands(ctx, node, f.e.Tenant, f.e.Node, 0, 32)
		must(t, e)
		if re == nil {
			if resolution.State != "COMPLETE" || admission.State != "ABANDONED" || len(queue) != 0 {
				t.Fatal("false abandonment", resolution, admission, len(queue))
			}
		} else if !errors.Is(re, ErrConflict) || admission.State != "ADMITTED" || len(queue) != 1 {
			t.Fatal("publication outcome", re, admission, len(queue))
		}
	}
}
func TestManagementResolutionHTTPExactScopeAndIdempotentReceipt(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	ctx := context.Background()
	raw, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	if _, e = f.r.ApplyEnrollment(ctx, f.p, id("pending-enroll"), "INITIAL_ENROLLMENT", raw, 0); e == nil {
		t.Fatal("missing interruption")
	}
	f.r.Fault = nil
	input := resolutionInput(t, f, id("pending-enroll"))
	path := "/api/v1/tenants/" + f.e.Tenant + "/operations/" + id("pending-enroll") + "/resolution"
	status, body := h.request(t, h.owner, "GET", path, nil)
	if status != 200 {
		t.Fatalf("preview %d %s", status, body)
	}
	var preview ResolutionPreview
	must(t, json.Unmarshal(body, &preview))
	if !preview.CanAbandon {
		t.Fatal(preview)
	}
	status, _ = h.request(t, h.viewer, "POST", path, input)
	if status != 403 {
		t.Fatal("viewer resolution", status)
	}
	wrong := input
	wrong.TargetDigest = id("wrong-request")
	status, _ = h.request(t, h.owner, "POST", path, wrong)
	if status != 409 {
		t.Fatal("wrong digest", status)
	}
	for _, suffix := range []string{"?unexpected=1", "?"} {
		status, _ = h.request(t, h.owner, "POST", path+suffix, input)
		if status == 200 {
			t.Fatal("query alias accepted")
		}
	}
	status, body = h.request(t, h.owner, "POST", path, input)
	if status != 200 {
		t.Fatalf("resolve %d %s", status, body)
	}
	first := append([]byte(nil), body...)
	status, body = h.request(t, h.owner, "POST", path, input)
	if status != 200 || !bytes.Equal(first, body) {
		t.Fatal("lost-reply replay changed")
	}
	status, body = h.request(t, h.owner, "GET", "/api/v1/tenants/"+f.e.Tenant+"/operations/"+id("pending-enroll"), nil)
	if status != 200 || !bytes.Contains(body, []byte("ABANDONED")) {
		t.Fatal("original receipt not fenced", status, string(body))
	}
}

type resolutionCrash struct {
	Directory             string
	Owner                 ed25519.PublicKey
	Signer                ed25519.PrivateKey
	Principal             Principal
	Tenant, Target, Point string
	Request               ResolveRequest
}

func TestManagementResolutionSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_RESOLUTION_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var in resolutionCrash
	must(t, json.Unmarshal(raw, &in))
	r, e := Open(Options{Directory: in.Directory, Owner: in.Owner, Signer: in.Signer})
	must(t, e)
	defer r.Close()
	r.Fault = func(point string) error {
		if point == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_, e = r.ResolveUnpublished(context.Background(), in.Principal, in.Tenant, in.Target, in.Request)
	must(t, e)
	t.Fatal("kill point absent")
}
func TestManagementResolutionSIGKILLRetainsCheckpointAndAbandonmentFence(t *testing.T) {
	for _, point := range []string{"management-resolution-checkpoint-durable", "management-resolution-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newFixture(t)
			raw := pendingEnrollment(t, f)
			input := resolutionInput(t, f, id("pending-enroll"))
			in := resolutionCrash{f.dir, f.options.Owner, f.options.Signer, f.p, f.e.Tenant, id("pending-enroll"), point, input}
			must(t, f.r.Close())
			f.r = nil
			data, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.dir, "resolution-child.json")
			must(t, os.WriteFile(file, data, 0600))
			child := exec.Command(os.Args[0], "-test.run=^TestManagementResolutionSIGKILLChild$", "-test.timeout=20s")
			child.Env = append(os.Environ(), "OUTPOST_RESOLUTION_KILL="+file)
			output, e := child.CombinedOutput()
			var status *exec.ExitError
			if !errors.As(e, &status) || status.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected child %v %s", e, output)
			}
			r, e := Open(f.options)
			must(t, e)
			f.r = r
			before, e := r.Operation(context.Background(), f.p, f.e.Tenant, in.Target)
			must(t, e)
			if point == "management-resolution-result-durable" && before.State != "ABANDONED" {
				t.Fatal("lost fence", before)
			}
			_, e = r.ResolveUnpublished(context.Background(), f.p, f.e.Tenant, in.Target, input)
			must(t, e)
			receipt, e := r.ApplyEnrollment(context.Background(), f.p, in.Target, "INITIAL_ENROLLMENT", raw, 0)
			must(t, e)
			if receipt.State != "ABANDONED" {
				t.Fatal(receipt)
			}
		})
	}
}

func TestManagementResolutionUnknownCacheNeverEstablishesAbsenceOfEffect(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt"} {
		t.Run(damage, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			f.enroll(t)
			cfg := configFixture(t, f)
			current := configurationMutation(t, f, cfg, "first-known-config", 0)
			current.PreviewDigest = storage.Hash(current.Document)
			_, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, current)
			must(t, e)
			cfg.Revision++
			candidate := configurationMutation(t, f, cfg, "unknown-cache-candidate", 1)
			candidate.PreviewDigest = storage.Hash(candidate.Document)
			f.r.Fault = interruptAt("management-config-intent-durable")
			if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, candidate); e == nil {
				t.Fatal("no interruption")
			}
			f.reopen(t)
			input := resolutionInput(t, f, candidate.Operation)
			before, e := f.r.store.Read("registry.json")
			must(t, e)
			cache := filepath.Join(f.dir, "config-"+f.e.Node, "cache.json")
			if damage == "missing" {
				must(t, os.Remove(cache))
			} else {
				must(t, os.WriteFile(cache, []byte("corrupt"), 0600))
			}
			preview, e := f.r.ResolutionPreview(ctx, f.p, f.e.Tenant, candidate.Operation)
			must(t, e)
			if preview.CanAbandon || preview.Reason != "STATE_UNAVAILABLE" {
				t.Fatal("unknown treated as absent", preview)
			}
			if _, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, candidate.Operation, input); e == nil {
				t.Fatal("unknown effect abandoned")
			}
			after, e := f.r.store.Read("registry.json")
			must(t, e)
			if !bytes.Equal(before, after) {
				t.Fatal("unknown resolution mutated journal")
			}
		})
	}
}
func TestManagementResolutionRetainsHistoricalScopeAfterLaterEnrollment(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.e.Domains = append(f.e.Domains, DomainAdmission{id("second-domain"), id("second-repository"), 1})
	f.enroll(t)
	next := f.e
	next.Revision++
	next.Domains = append([]DomainAdmission(nil), next.Domains[1:]...)
	raw, e := SignEnrollment(next, f.owner)
	must(t, e)
	target := id("remove-original-domain")
	f.r.Fault = interruptAt("management-enrollment-intent-durable")
	if _, e = f.r.ApplyEnrollment(ctx, f.p, target, "POLICY_CHANGE", raw, 1); e == nil {
		t.Fatal("no interruption")
	}
	f.reopen(t)
	_, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, target, resolutionInput(t, f, target))
	must(t, e)
	_, e = f.r.ApplyEnrollment(ctx, f.p, id("apply-removal-later"), "POLICY_CHANGE", raw, 1)
	must(t, e)
	f.reopen(t)
	restricted := f.p
	restricted.Scopes = []Scope{{f.e.Tenant, id("second-domain")}}
	if _, e = f.r.ResolutionPreview(ctx, restricted, f.e.Tenant, target); !errors.Is(e, ErrUnavailable) {
		t.Fatal("historical scope shrank", e)
	}
	if _, e = f.r.Operation(ctx, restricted, f.e.Tenant, target); !errors.Is(e, ErrUnavailable) {
		t.Fatal("old scope receipt leaked", e)
	}
	preview, e := f.r.ResolutionPreview(ctx, f.p, f.e.Tenant, target)
	must(t, e)
	if len(preview.Domains) != 2 || preview.State != "ABANDONED" {
		t.Fatal(preview)
	}
}
func TestManagementResolutionRejectsInvalidSequenceAndFormatDowngrade(t *testing.T) {
	for _, damage := range []string{"sequence", "format"} {
		t.Run(damage, func(t *testing.T) {
			f := newFixture(t)
			pendingEnrollment(t, f)
			target := id("pending-enroll")
			_, e := f.r.ResolveUnpublished(context.Background(), f.p, f.e.Tenant, target, resolutionInput(t, f, target))
			must(t, e)
			s, e := f.r.load()
			must(t, e)
			if damage == "sequence" {
				v := s.Resolutions[target]
				v.Audit.Sequence = s.Operations[target].Audit.Sequence
				s.Resolutions[target] = v
			} else {
				s.Format = registryFormat
			}
			must(t, f.r.save(s))
			if _, e = f.r.load(); !errors.Is(e, ErrInvalid) {
				t.Fatal("invalid resolution fence accepted", damage, e)
			}
		})
	}
}
