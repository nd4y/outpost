package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/capture"
	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/worker"
)

// CompanionIngress enrolls a second required holder in the private source
// installation. Its endpoint and owner-signed authority are bound to that
// installation before any capture.
type CompanionIngress struct {
	Endpoint      string `json:"endpoint"`
	AuthorityFile string `json:"authorityFile"`
}

func (a *Agent) loadCompanion() error {
	if a.b.Companion == nil {
		return nil
	}
	selected := *a.b.Companion
	a.b.Companion = &selected
	if a.b.Profile.MinimumCopies != 2 || !policy.Endpoint(selected.Endpoint) || selected.Endpoint == a.b.Endpoint {
		return ErrInvalid
	}
	raw, e := worker.ReadPrivate(selected.AuthorityFile, ingress.MaxDocument)
	if e != nil {
		return e
	}
	companion, e := ingress.VerifyAuthorityDocument(raw, a.b.Local.Owner)
	if e != nil {
		return e
	}
	if !sameReceiverPair(a.anchor, companion) {
		return ErrInvalid
	}
	if a.b.Profile.ReleasePolicy != "" {
		targets := a.b.Profile.CopyTargets
		if len(targets) != 2 ||
			!(targets[0] == a.anchor.Ingress && targets[1] == companion.Ingress ||
				targets[1] == a.anchor.Ingress && targets[0] == companion.Ingress) {
			return ErrInvalid
		}
	}
	a.companion, a.companionAuthority = companion, raw
	return nil
}

func sameReceiverPair(primary, companion ingress.Authority) bool {
	if primary.Ingress == companion.Ingress {
		return false
	}
	primary.Ingress = companion.Ingress
	return ingress.SameAuthorityScope(primary, companion) && primary.Revision == companion.Revision &&
		primary.NotBefore == companion.NotBefore && primary.ExpiresUnix == companion.ExpiresUnix
}

func (a *Agent) verifyCompanionAuthority(primary ingress.Authority, raw []byte) error {
	companion, e := ingress.VerifyAuthorityDocument(raw, a.b.Local.Owner)
	if e != nil {
		return e
	}
	if companion.Ingress != a.companion.Ingress || !sameReceiverPair(primary, companion) {
		return ingress.ErrDenied
	}
	return nil
}

const companionReceiptFormat = "outpost-companion-receipt-1"

type companionReceipt struct {
	Format    string          `json:"format"`
	Intent    string          `json:"intent"`
	Receipt   ingress.Receipt `json:"receipt"`
	Signature []byte          `json:"signature,omitempty"`
}

// parallelSink preserves the primary receipt and existing release protocol.
// Its second holder is required, so accepted objects and the final catalog can
// be verified on both independently before release.
type parallelSink struct {
	*ingress.Client
	companion               *ingress.Client
	intention               ingress.Intent
	primary, primaryBinding string
	binding                 string
	records                 *statefile.Store
	writer                  ed25519.PrivateKey
	split                   bool
	replaying               bool
	next                    atomic.Uint64
}

func (a *Agent) openParallelSink(i ingress.Intent, prefix string, authority []byte, primary *ingress.Client, limits peer.Limits, initialize, cleanup bool) (*parallelSink, error) {
	primaryID := i.Ingress
	i.Ingress = a.companion.Ingress
	i.Authority = storage.Hash(authority)
	raw, e := ingress.SignIntent(i, authority, a.b.Local.Owner, a.writer, time.Unix(i.NotBefore, 0))
	if e != nil {
		return nil, e
	}
	var companion *ingress.Client
	if cleanup {
		companion, e = ingress.NewCleanupClient(a.b.Companion.Endpoint, authority, raw, a.b.Local.Owner, a.cert, a.roots, limits)
	} else {
		companion, e = ingress.NewClient(a.b.Companion.Endpoint, authority, raw, a.b.Local.Owner, a.cert, a.roots, limits)
	}
	if e != nil {
		return nil, e
	}
	dir := path.Join(prefix, "input")
	store, e := statefile.OpenAt(a.root, dir, maxState, initialize)
	if e != nil {
		companion.Close()
		return nil, e
	}
	store.Admit = a.admission(dir)
	return &parallelSink{Client: primary, companion: companion, intention: i, primary: primaryID, primaryBinding: primary.IntentID(), binding: storage.Hash(raw), records: store, writer: a.writer, split: a.b.Profile.ReleasePolicy == capture.PairedSplitCoverage, replaying: !initialize}, nil
}

func (s *parallelSink) Close() {
	s.Client.Close()
	s.companion.Close()
	_ = s.records.Close()
}

func (s *parallelSink) ParallelWrites() int { return 2 }

func (s *parallelSink) CoverageBindings() map[string]string {
	return map[string]string{s.primary: s.primaryBinding, s.intention.Ingress: s.binding}
}

func (s *parallelSink) Coverage(ctx context.Context, raw []byte) ([]ingress.CoverageReceipt, error) {
	type result struct {
		receipt ingress.CoverageReceipt
		err     error
	}
	var primaryPeer, companionPeer *ingress.Client
	if s.split {
		primaryPeer, companionPeer = s.companion, s.Client
	}
	done := make(chan result, 1)
	go func() {
		receipt, err := s.companion.StageCoverage(ctx, raw, companionPeer)
		done <- result{receipt, err}
	}()
	primary, err := s.Client.StageCoverage(ctx, raw, primaryPeer)
	other := <-done
	if err != nil || other.err != nil {
		return nil, errors.Join(err, other.err)
	}
	return []ingress.CoverageReceipt{primary, other.receipt}, nil
}

func (s *parallelSink) Begin(ctx context.Context) error {
	if e := s.Client.Begin(ctx); e != nil {
		return e
	}
	return s.companion.Begin(ctx)
}

func (s *parallelSink) selected(ref filekit.Object) *ingress.Client {
	if ingress.CoverageHolder(ref.ID, s.primary, s.intention.Ingress) == s.primary {
		return s.Client
	}
	return s.companion
}

func (s *parallelSink) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	if s.split {
		return s.selected(ref).Read(ctx, ref)
	}
	return s.Client.Read(ctx, ref)
}

func (s *parallelSink) Check(ctx context.Context, ref filekit.Object) error {
	if s.split {
		return s.selected(ref).Check(ctx, ref)
	}
	if e := s.Client.Check(ctx, ref); e != nil {
		return e
	}
	return s.companion.Check(ctx, ref)
}

func (s *parallelSink) Write(ctx context.Context, ref filekit.Object, payload []byte) (bool, error) {
	if s.split {
		client := s.selected(ref)
		e := client.Check(ctx, ref)
		if e == nil {
			return false, nil
		}
		if !errors.Is(e, os.ErrNotExist) {
			return false, e
		}
		return client.Write(ctx, ref, payload)
	}
	origin, destination := s.Client, s.companion
	if s.next.Add(1)%2 == 0 {
		origin, destination = destination, origin
	}
	e := origin.Check(ctx, ref)
	if e == nil {
		return false, destination.PullStaged(ctx, origin, ref)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	// After a restart the other holder may already have accepted this
	// exact ciphertext. Reuse it without asking the source to resend.
	if s.replaying {
		e = destination.Check(ctx, ref)
		if e == nil {
			return false, origin.PullStaged(ctx, destination, ref)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return false, e
		}
	}
	created, e := origin.Write(ctx, ref, payload)
	if e != nil {
		return false, e
	}
	if e = destination.PullStaged(ctx, origin, ref); e != nil {
		return false, e
	}
	return created, nil
}

func (s *parallelSink) loadReceipt(generation string) (ingress.Receipt, error) {
	var record companionReceipt
	raw, e := s.records.Read("companion-receipt.json")
	if e != nil {
		return record.Receipt, e
	}
	if storage.Decode(raw, &record, 4096) != nil || record.Format != companionReceiptFormat || record.Intent != s.binding {
		return record.Receipt, ErrInvalid
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(raw, canonical) {
		return record.Receipt, ErrInvalid
	}
	sig := record.Signature
	record.Signature = nil
	payload, _ := json.Marshal(record)
	if !ed25519.Verify(s.writer.Public().(ed25519.PublicKey), payload, sig) {
		return record.Receipt, ErrInvalid
	}
	r, i := record.Receipt, s.intention
	if r.Generation != generation || r.Operation != i.Operation || r.Ingress != i.Ingress || r.Tenant != i.Tenant || r.Domain != i.Domain ||
		r.NewBytes < 0 || r.NewBytes > i.MaxBytes || r.NewObjects < 0 || r.NewObjects > i.MaxObjects ||
		r.VerifiedAt < i.NotBefore || r.VerifiedAt >= i.ExpiresUnix || r.VerifiedAt > time.Now().Unix() {
		return r, ErrInvalid
	}
	return r, nil
}

func (s *parallelSink) FinishStep(ctx context.Context, catalog []byte) (generation.BatchResult, *ingress.Receipt, error) {
	for attempt := 0; ; attempt++ {
		progress, receipt, e := s.finishStep(ctx, catalog)
		if s.split && partitionPending(e) {
			timer := time.NewTimer(250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				return progress, nil, nil
			case <-ctx.Done():
				return progress, nil, ctx.Err()
			}
		}
		if e == nil || attempt == 2 || ctx.Err() != nil || !retryablePublication(e) {
			return progress, receipt, e
		}
		// The catalog is immutable and the receiver persists its verification
		// cursor. A lost reply can be replayed without sending source payload.
		timer := time.NewTimer(time.Duration(attempt+1) * 250 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return progress, nil, ctx.Err()
		}
	}
}

func partitionPending(e error) bool {
	if joined, ok := e.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !partitionPending(child) {
				return false
			}
		}
		return true
	}
	return errors.Is(e, ingress.ErrIncomplete)
}

func retryablePublication(e error) bool {
	if joined, ok := e.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !retryablePublication(child) {
				return false
			}
		}
		return true
	}
	return errors.Is(e, ingress.ErrUnavailable) || errors.Is(e, context.DeadlineExceeded)
}

func (s *parallelSink) finishStep(ctx context.Context, catalog []byte) (generation.BatchResult, *ingress.Receipt, error) {
	_, e := s.loadReceipt(storage.Hash(catalog))
	if e == nil {
		return s.Client.FinishStep(ctx, catalog)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return generation.BatchResult{}, nil, e
	}
	type companionResult struct {
		receipt *ingress.Receipt
		err     error
	}
	done := make(chan companionResult, 1)
	go func() {
		_, receipt, err := s.companion.FinishStep(ctx, catalog)
		done <- companionResult{receipt, err}
	}()
	progress, primary, e := s.Client.FinishStep(ctx, catalog)
	other := <-done
	if other.err != nil || other.receipt == nil {
		return progress, nil, errors.Join(e, other.err)
	}
	record := companionReceipt{Format: companionReceiptFormat, Intent: s.binding, Receipt: *other.receipt}
	payload, _ := json.Marshal(record)
	record.Signature = ed25519.Sign(s.writer, payload)
	raw, _ := json.Marshal(record)
	if err := s.records.Write("companion-receipt.json", raw); err != nil {
		return progress, nil, errors.Join(e, err)
	}
	return progress, primary, e
}

func (s *parallelSink) SettlementReceipt(ctx context.Context) (ingress.Receipt, error) {
	receipt, e := s.Client.SettlementReceipt(ctx)
	if e != nil {
		return ingress.Receipt{}, e
	}
	if _, e = s.loadReceipt(receipt.Generation); e != nil {
		return ingress.Receipt{}, e
	}
	return receipt, nil
}

func (s *parallelSink) AcknowledgeStep(ctx context.Context, primary ingress.Receipt) (ingress.Acknowledgement, error) {
	receipt, e := s.loadReceipt(primary.Generation)
	if e != nil {
		return ingress.Acknowledgement{}, e
	}
	ack, e := s.companion.AcknowledgeStep(ctx, receipt)
	if e != nil {
		return ingress.Acknowledgement{}, e
	}
	if !ack.Clean {
		ack.Receipt = primary
		return ack, nil
	}
	return s.Client.AcknowledgeStep(ctx, primary)
}
