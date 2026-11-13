package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

func unseenCommand(t *testing.T, f *fixture) (UnseenRequest, UnseenResolutionRequest) {
	t.Helper()
	_, req, _ := commandFixture(t, f)
	original := UnseenRequest{Node: f.e.Node, Command: &req}
	preview, e := f.r.UnseenRefusalPreview(context.Background(), f.p, f.e.Tenant, req.Operation, original)
	must(t, e)
	if !preview.CanAbandon || preview.State != "UNCONFIRMED" || preview.Reason != "UNSEEN_UNPUBLISHED" {
		t.Fatal(preview)
	}
	return original, UnseenResolutionRequest{ResolveRequest{id("unseen-resolution"), preview.TargetDigest, "ABANDON_UNPUBLISHED"}, original}
}
func TestManagementUnseenRefusalAtomicReceiptReplayAndNoDelivery(t *testing.T) {
	f := newJournalFixture(t, true)
	original, input := unseenCommand(t, f)
	ctx := context.Background()
	target := original.Command.Operation
	before, e := f.r.load()
	must(t, e)
	prior, e := f.r.store.Read("registry.json")
	must(t, e)
	receipt, e := f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, target, input)
	must(t, e)
	after, e := f.r.load()
	must(t, e)
	if after.Format != unseenFormat || after.Revision != before.Revision+1 || len(after.UnseenRefusals) != 1 || len(after.CommandOperations) != 0 {
		t.Fatal("non-atomic or runnable refusal", after.Revision)
	}
	predecessor, e := f.r.store.Read("registry-v1-" + storage.Hash(prior) + ".json")
	must(t, e)
	if !bytes.Equal(prior, predecessor) {
		t.Fatal("predecessor changed")
	}
	f.reopen(t)
	replay, e := f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, target, input)
	must(t, e)
	if replay != receipt {
		t.Fatal("refreshed receipt")
	}
	replay, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, target, input.Resolution)
	must(t, e)
	if replay != receipt {
		t.Fatal("lost-reply readback changed")
	}
	targetReceipt, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, *original.Command)
	must(t, e)
	if targetReceipt.State != "ABANDONED" || targetReceipt.ErrorCode != "OWNER_ABANDONED" {
		t.Fatal(targetReceipt)
	}
	for _, operation := range []string{target, input.Resolution.Operation} {
		got, e := f.r.Operation(ctx, f.p, f.e.Tenant, operation)
		must(t, e)
		if got.Operation != operation {
			t.Fatal(got)
		}
	}
	preview, e := f.r.ResolutionPreview(ctx, f.p, f.e.Tenant, target)
	must(t, e)
	if preview.CanAbandon || preview.Reason != "ALREADY_ABANDONED" {
		t.Fatal(preview)
	}
	audit, _, e := f.r.Audit(ctx, f.p, f.e.Tenant, 0, 32)
	must(t, e)
	if audit[len(audit)-1].Action != "ABANDON_UNSEEN" {
		t.Fatal(audit)
	}
	result, e := f.r.Reconcile(ctx, []Principal{f.p}, 0, 32)
	must(t, e)
	if len(result.Items) != 0 {
		t.Fatal("refusal published", result)
	}
}
func TestManagementUnseenConfigurationRefusalKeepsExactSignedBytesAndSnapshot(t *testing.T) {
	f := newJournalFixture(t, true)
	f.enroll(t)
	ctx := context.Background()
	cfg := configFixture(t, f)
	req := configurationMutation(t, f, cfg, "unseen-config", 0)
	req.PreviewDigest = storage.Hash(req.Document)
	original := UnseenRequest{Node: f.e.Node, Configuration: &req}
	preview, e := f.r.UnseenRefusalPreview(ctx, f.p, f.e.Tenant, req.Operation, original)
	must(t, e)
	input := UnseenResolutionRequest{ResolveRequest{id("refuse-config"), preview.TargetDigest, "ABANDON_UNPUBLISHED"}, original}
	_, e = f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, req.Operation, input)
	must(t, e)
	receipt, e := f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, req)
	must(t, e)
	if receipt.State != "ABANDONED" {
		t.Fatal(receipt)
	}
	if _, e = f.r.Configuration(ctx, f.p, f.e.Tenant, f.e.Node); e == nil {
		t.Fatal("configuration published")
	}
	raw, trust, _ := snapshotBytes(t, f)
	inspection, e := InspectSnapshot(ctx, bytes.NewReader(raw), trust, 8<<20)
	must(t, e)
	found := 0
	for _, r := range inspection.Receipts {
		if r.Operation == req.Operation && r.State == "ABANDONED" || r.Operation == input.Resolution.Operation && r.State == "COMPLETE" {
			found++
		}
	}
	if found != 2 {
		t.Fatal(inspection.Receipts)
	}
	req.Expected++
	if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, req); !errors.Is(e, ErrConflict) {
		t.Fatal("changed request reused ID", e)
	}
	// A missing original cannot erase the signed fence, but cannot produce a complete metadata recovery package.
	must(t, os.Remove(filepath.Join(f.dir, "blobs", "candidate-"+storage.Hash(req.Document)+".json")))
	receipt, e = f.r.Operation(ctx, f.p, f.e.Tenant, req.Operation)
	must(t, e)
	if receipt.State != "ABANDONED" {
		t.Fatal(receipt)
	}
	var damaged bytes.Buffer
	if _, e = f.r.Snapshot(ctx, &damaged, 1, id("private-profile"), 8<<20); e == nil {
		t.Fatal("snapshot omitted original proof")
	}
}
func TestManagementUnseenRefusalRequiresJournalCurrentOwnerAndExactScope(t *testing.T) {
	for _, damage := range []string{"no-journal", "operator", "partial-domain", "foreign-tenant", "different-node", "changed-request", "cancelled", "admitted", "published", "expired-node", "repository"} {
		t.Run(damage, func(t *testing.T) {
			f := newJournalFixture(t, damage != "no-journal")
			_, req, _ := commandFixture(t, f)
			ctx := context.Background()
			original := UnseenRequest{Node: f.e.Node, Command: &req}
			input := UnseenResolutionRequest{ResolveRequest{id("refusal"), commandRequestDigest(f.p, f.e.Node, req), "ABANDON_UNPUBLISHED"}, original}
			p := f.p
			tenant := f.e.Tenant
			switch damage {
			case "operator":
				p.Roles = []string{"operator"}
			case "partial-domain":
				p.Scopes = []Scope{{tenant, id("second-domain")}}
			case "foreign-tenant":
				tenant = id("foreign")
			case "different-node":
				input.Original.Node = id("different-node")
			case "changed-request":
				input.Resolution.TargetDigest = id("not-original")
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "admitted":
				f.r.Fault = interruptAt("management-command-intent-durable")
				_, _ = f.r.AdmitCommand(ctx, p, tenant, f.e.Node, req)
				f.reopen(t)
			case "published":
				_, e := f.r.AdmitCommand(ctx, p, tenant, f.e.Node, req)
				must(t, e)
			case "expired-node":
				f.e.Revision++
				f.e.NotBefore = time.Now().Unix() - 600
				f.e.ExpiresUnix = time.Now().Unix() - 1
				raw, e := SignEnrollment(f.e, f.owner)
				must(t, e)
				state, e := f.r.load()
				must(t, e)
				state.Enrollments[f.e.Node] = raw
				must(t, f.r.save(state))
			case "repository":
				a, e := command.VerifyAuthority(req.Authority, f.options.Owner)
				must(t, e)
				a.Repository = id("different-repository")
				req.Authority, e = command.SignAuthority(a, f.owner)
				must(t, e)
				input.Resolution.TargetDigest = commandRequestDigest(f.p, f.e.Node, req)
			}
			if _, e := f.r.RefuseUnseen(ctx, p, tenant, req.Operation, input); e == nil {
				t.Fatal("unsafe refusal accepted")
			}
			if damage != "repository" {
				state, e := f.r.load()
				must(t, e)
				if len(state.UnseenRefusals) != 0 {
					t.Fatal("failed request left a fence")
				}
			}
		})
	}
}
func TestManagementUnseenRefusalAcceptsExpiredExecutionWithoutExecutingIt(t *testing.T) {
	f := newJournalFixture(t, true)
	original, input := unseenCommand(t, f)
	original.Command.ExpiresUnix = time.Now().Unix() - 1
	input.Original = original
	input.Resolution.TargetDigest = commandRequestDigest(f.p, f.e.Node, *original.Command)
	_, e := f.r.RefuseUnseen(context.Background(), f.p, f.e.Tenant, original.Command.Operation, input)
	must(t, e)
}
func TestManagementUnseenRefusalCompetesWithAdmissionUnderOneLock(t *testing.T) {
	f := newJournalFixture(t, true)
	original, input := unseenCommand(t, f)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, errs[0] = f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, original.Command.Operation, input)
	}()
	go func() {
		defer wg.Done()
		_, errs[1] = f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, *original.Command)
	}()
	wg.Wait()
	s, e := f.r.load()
	must(t, e)
	_, refused := s.UnseenRefusals[original.Command.Operation]
	_, admitted := s.CommandOperations[original.Command.Operation]
	if refused == admitted || errs[0] != nil && errs[1] != nil {
		t.Fatal("neither or both branches committed", errs)
	}
}

func TestManagementUnseenPreservesRegistry2AndFencesEveryAdmissionID(t *testing.T) {
	f := newJournalFixture(t, true)
	original, input := unseenCommand(t, f)
	ctx := context.Background()
	pending := *original.Command
	pending.Operation = id("known-pending")
	f.r.Fault = interruptAt("management-command-intent-durable")
	_, e := f.r.AdmitCommand(ctx, f.p, f.e.Tenant, f.e.Node, pending)
	if e == nil {
		t.Fatal("missing interruption")
	}
	f.reopen(t)
	known := resolutionInput(t, f, pending.Operation)
	_, e = f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, pending.Operation, known)
	must(t, e)
	prior, e := f.r.store.Read("registry.json")
	must(t, e)
	before, e := f.r.load()
	must(t, e)
	if before.Format != resolutionFormat {
		t.Fatal(before.Format)
	}
	_, e = f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, original.Command.Operation, input)
	must(t, e)
	s, e := f.r.load()
	must(t, e)
	checkpoint, e := f.r.store.Read("registry-v2-" + storage.Hash(prior) + ".json")
	must(t, e)
	if !bytes.Equal(checkpoint, prior) || s.LegacyCheckpoint != before.LegacyCheckpoint || len(s.Resolutions) != 1 || s.Revision != before.Revision+1 {
		t.Fatal("registry2 migration lost history")
	}
	enrollment, e := SignEnrollment(f.e, f.owner)
	must(t, e)
	for _, operation := range []string{original.Command.Operation, input.Resolution.Operation} {
		if !resolutionID(s, operation) || !managementIDUsed(s, operation) {
			t.Fatal("ID not fenced")
		}
		if _, e = f.r.ApplyEnrollment(ctx, f.p, operation, "INITIAL_ENROLLMENT", enrollment, 0); !errors.Is(e, ErrConflict) {
			t.Fatal("enrollment reused fenced ID", e)
		}
		cfg := configurationMutation(t, f, configFixture(t, f), "fenced-config", 0)
		cfg.Operation = operation
		cfg.PreviewDigest = storage.Hash(cfg.Document)
		if _, e = f.r.ApplyConfiguration(ctx, f.p, f.e.Tenant, f.e.Node, cfg); !errors.Is(e, ErrConflict) {
			t.Fatal("configuration reused fenced ID", e)
		}
	}
	// Existing known resolutions still work after the new format was introduced.
	got, e := f.r.ResolveUnpublished(ctx, f.p, f.e.Tenant, pending.Operation, known)
	must(t, e)
	if got.State != "COMPLETE" {
		t.Fatal(got)
	}
	snapshot, trust, _ := snapshotBytes(t, f)
	_, e = InspectSnapshot(ctx, bytes.NewReader(snapshot), trust, 8<<20)
	must(t, e)
}

func TestManagementUnseenIDCollisionAndMissingJournalNeverForgetRequest(t *testing.T) {
	for _, damage := range []string{"target-resolution", "resolution-enrollment", "resolution-refusal", "missing-copy", "missing-anchor", "changed-copy"} {
		t.Run(damage, func(t *testing.T) {
			f := newJournalFixture(t, true)
			original, input := unseenCommand(t, f)
			ctx := context.Background()
			switch damage {
			case "target-resolution":
				input.Resolution.Operation = original.Command.Operation
			case "resolution-enrollment":
				input.Resolution.Operation = id("enroll")
			case "resolution-refusal":
				_, e := f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, original.Command.Operation, input)
				must(t, e)
				original.Command.Operation = id("next-unseen")
				input.Original = original
				input.Resolution.TargetDigest = commandRequestDigest(f.p, f.e.Node, *original.Command)
			case "missing-copy":
				must(t, os.Remove(filepath.Join(f.dir, registryJournalCopyName)))
			case "missing-anchor":
				must(t, os.Remove(filepath.Join(f.dir, registryJournalAnchorName)))
			case "changed-copy":
				must(t, os.WriteFile(filepath.Join(f.dir, registryJournalCopyName), []byte("{}"), 0600))
			}
			if _, e := f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, original.Command.Operation, input); e == nil {
				t.Fatal("unhealthy or colliding refusal admitted")
			}
		})
	}
}

func TestManagementUnseenCapacityCancellationAndGuardFailBeforeFence(t *testing.T) {
	for _, damage := range []string{"quota", "cancel-after-proof", "guard-after-proof"} {
		t.Run(damage, func(t *testing.T) {
			f := newJournalFixture(t, true)
			original, input := unseenCommand(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			revoked := false
			switch damage {
			case "quota":
				f.r.blobs.Admit = func(string, int) (func(bool) error, error) { return nil, statefile.ErrCapacity }
			case "cancel-after-proof":
				f.r.Fault = func(point string) error {
					if point == "management-unseen-request-durable" {
						cancel()
					}
					return nil
				}
			case "guard-after-proof":
				f.r.guard = func(context.Context) error {
					if revoked {
						return ErrDenied
					}
					return nil
				}
				f.r.Fault = func(point string) error {
					if point == "management-unseen-request-durable" {
						revoked = true
					}
					return nil
				}
			}
			if _, e := f.r.RefuseUnseen(ctx, f.p, f.e.Tenant, original.Command.Operation, input); e == nil {
				t.Fatal("failed admission left a successful refusal")
			}
			f.r.guard = nil
			f.r.Fault = nil
			s, e := f.r.load()
			must(t, e)
			if len(s.UnseenRefusals) != 0 || len(s.CommandOperations) != 0 {
				t.Fatal("partial runnable intent or fence")
			}
		})
	}
}

func TestManagementUnseenHTTPExplicitPreviewConfirmationAndReadback(t *testing.T) {
	h := newHTTPFixture(t)
	f := h.f
	f.r.journalCopy = true
	must(t, f.r.store.WithLock(context.Background(), func() error { return f.r.enableRegistryJournal(context.Background()) }))
	f.options.JournalCopy = true
	original, input := unseenCommand(t, f)
	target := original.Command.Operation
	path := "/api/v1/tenants/" + f.e.Tenant + "/operations/" + target
	code, _ := h.request(t, h.owner, http.MethodGet, path+"/resolution", nil)
	if code != 404 {
		t.Fatal("unseen request silently admitted", code)
	}
	code, _ = h.request(t, h.viewer, http.MethodPost, path+"/refusal-preview", original)
	if code != 403 {
		t.Fatal("viewer previewed owner mutation", code)
	}
	code, raw := h.request(t, h.owner, http.MethodPost, path+"/refusal-preview", original)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	var preview ResolutionPreview
	must(t, json.Unmarshal(raw, &preview))
	if !preview.CanAbandon || preview.TargetDigest != input.Resolution.TargetDigest {
		t.Fatal(preview)
	}
	code, raw = h.request(t, h.owner, http.MethodPost, path+"/refusal", input)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	var receipt Receipt
	must(t, json.Unmarshal(raw, &receipt))
	code, raw = h.request(t, h.owner, http.MethodPost, path+"/resolution", input.Resolution)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	var again Receipt
	must(t, json.Unmarshal(raw, &again))
	if again != receipt {
		t.Fatal("replay refreshed")
	}
	code, raw = h.request(t, h.owner, http.MethodGet, path, nil)
	if code != 200 {
		t.Fatal(code, string(raw))
	}
	must(t, json.Unmarshal(raw, &again))
	if again.State != "ABANDONED" {
		t.Fatal(again)
	}
}

func TestManagementUnseenPreviousReaderRefusesWithoutChangingState(t *testing.T) {
	binary := os.Getenv("OUTPOST_PREDECESSOR_READER")
	if binary == "" {
		t.Skip("separately built pinned predecessor reader required")
	}
	if !filepath.IsAbs(binary) {
		t.Fatal("absolute predecessor binary required")
	}
	f := newJournalFixture(t, true)
	original, input := unseenCommand(t, f)
	_, e := f.r.RefuseUnseen(context.Background(), f.p, f.e.Tenant, original.Command.Operation, input)
	must(t, e)
	before, e := f.r.store.Read("registry.json")
	must(t, e)
	in := unseenCrash{Directory: f.dir, Owner: f.options.Owner, Signer: f.options.Signer}
	raw, e := json.Marshal(in)
	must(t, e)
	file := filepath.Join(f.dir, "predecessor-input.json")
	must(t, os.WriteFile(file, raw, 0600))
	must(t, f.r.Close())
	f.r = nil
	child := exec.Command(binary, "-test.run=^TestPredecessorRefusesRegistry3$", "-test.v", "-test.timeout=20s")
	child.Env = append(os.Environ(), "OUTPOST_PREDECESSOR_INPUT="+file)
	output, e := child.CombinedOutput()
	if e != nil {
		t.Fatalf("predecessor accepted or changed state: %v %s", e, output)
	}
	after, e := os.ReadFile(filepath.Join(f.dir, "registry.json"))
	must(t, e)
	if !bytes.Equal(before, after) {
		t.Fatal("predecessor changed signed registry")
	}
	f.r, e = Open(f.options)
	must(t, e)
}

type unseenCrash struct {
	Directory             string
	Owner                 ed25519.PublicKey
	Signer                ed25519.PrivateKey
	Principal             Principal
	Tenant, Target, Point string
	Input                 UnseenResolutionRequest
}

func TestManagementUnseenSIGKILLChild(t *testing.T) {
	file := os.Getenv("OUTPOST_UNSEEN_KILL")
	if file == "" {
		t.Skip("child only")
	}
	raw, e := os.ReadFile(file)
	must(t, e)
	var in unseenCrash
	must(t, json.Unmarshal(raw, &in))
	r, e := Open(Options{Directory: in.Directory, Owner: in.Owner, Signer: in.Signer, JournalCopy: true})
	must(t, e)
	defer r.Close()
	r.Fault = func(point string) error {
		if point == in.Point {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
		return nil
	}
	_, e = r.RefuseUnseen(context.Background(), in.Principal, in.Tenant, in.Target, in.Input)
	must(t, e)
	t.Fatal("kill point absent")
}
func TestManagementUnseenSIGKILLBeforeAndAfterAtomicFence(t *testing.T) {
	for _, point := range []string{"management-unseen-request-durable", "management-unseen-predecessor-durable", "management-registry-copy-durable", "management-registry-anchor-durable", "management-unseen-result-durable"} {
		t.Run(point, func(t *testing.T) {
			f := newJournalFixture(t, true)
			original, input := unseenCommand(t, f)
			target := original.Command.Operation
			in := unseenCrash{f.dir, f.options.Owner, f.options.Signer, f.p, f.e.Tenant, target, point, input}
			must(t, f.r.Close())
			f.r = nil
			raw, e := json.Marshal(in)
			must(t, e)
			file := filepath.Join(f.dir, "unseen-child.json")
			must(t, os.WriteFile(file, raw, 0600))
			child := exec.Command(os.Args[0], "-test.run=^TestManagementUnseenSIGKILLChild$", "-test.timeout=20s")
			child.Env = append(os.Environ(), "OUTPOST_UNSEEN_KILL="+file)
			output, e := child.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
				t.Fatalf("unexpected child %v %s", e, output)
			}
			r, e := Open(f.options)
			if point == "management-registry-copy-durable" || point == "management-registry-anchor-durable" {
				if !errors.Is(e, ErrRegistryJournal) {
					if r != nil {
						r.Close()
					}
					t.Fatal("interrupted journal trusted", e)
				}
				r, e = RecoverRegistry(context.Background(), f.options)
			}
			must(t, e)
			f.r = r
			_, e = r.RefuseUnseen(context.Background(), f.p, f.e.Tenant, target, input)
			must(t, e)
			got, e := r.AdmitCommand(context.Background(), f.p, f.e.Tenant, f.e.Node, *original.Command)
			must(t, e)
			if got.State != "ABANDONED" {
				t.Fatal(got)
			}
		})
	}
}
