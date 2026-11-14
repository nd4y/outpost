package sourceagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path"
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
	if a.b.Profile.MinimumCopies != 2 && !a.b.Standby || !policy.Endpoint(selected.Endpoint) || selected.Endpoint == a.b.Endpoint {
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
	if a.b.Reserve == nil && (a.b.Profile.ReleasePolicy != "" || a.b.Standby) {
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
	alternate               *ingress.Client
	intention               ingress.Intent
	primary, primaryBinding string
	binding                 string
	records                 *statefile.Store
	writer                  ed25519.PrivateKey
	settling                bool
	split                   bool
	recoverRoute            bool
	replaying               bool
	distribution            ingressDistribution
}

func (a *Agent) companionIntent(i ingress.Intent, authority []byte) (ingress.Intent, []byte, error) {
	return a.receiverIntent(i, a.companion.Ingress, authority)
}

func (a *Agent) receiverIntent(i ingress.Intent, receiver string, authority []byte) (ingress.Intent, []byte, error) {
	i.Ingress = receiver
	i.Authority = storage.Hash(authority)
	raw, err := ingress.SignIntent(i, authority, a.b.Local.Owner, a.writer, time.Unix(i.NotBefore, 0))
	return i, raw, err
}

func (a *Agent) openParallelSink(i ingress.Intent, prefix, companionID, endpoint string, authority []byte, primary *ingress.Client, limits peer.Limits, initialize, cleanup bool, settlement []byte) (*parallelSink, error) {
	primaryID := i.Ingress
	i, raw, e := a.receiverIntent(i, companionID, authority)
	if e != nil {
		return nil, e
	}
	var companion *ingress.Client
	if len(settlement) != 0 {
		companion, e = ingress.NewSettlementClient(endpoint, authority, raw, settlement, a.b.Local.Owner, a.cert, a.roots, limits)
	} else if cleanup {
		companion, e = ingress.NewCleanupClient(endpoint, authority, raw, a.b.Local.Owner, a.cert, a.roots, limits)
	} else {
		companion, e = ingress.NewClient(endpoint, authority, raw, a.b.Local.Owner, a.cert, a.roots, limits)
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
	return &parallelSink{Client: primary, companion: companion, intention: i, primary: primaryID, primaryBinding: primary.IntentID(), binding: storage.Hash(raw), records: store, writer: a.writer, settling: len(settlement) != 0, split: a.b.Profile.ReleasePolicy == capture.PairedSplitCoverage, replaying: !initialize}, nil
}

func (s *parallelSink) Close() {
	s.Client.Close()
	s.companion.Close()
	if s.alternate != nil {
		s.alternate.Close()
	}
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

func (s *parallelSink) splitOwner(ref filekit.Object) int {
	if ingress.CoverageHolder(ref.ID, s.primary, s.intention.Ingress) == s.primary {
		return 0
	}
	return 1
}

func (s *parallelSink) Read(ctx context.Context, ref filekit.Object) ([]byte, error) {
	if s.split {
		holders := [2]*ingress.Client{s.Client, s.companion}
		owner := s.splitOwner(ref)
		b, err := holders[owner].Read(ctx, ref)
		if !s.replaying || !errors.Is(err, os.ErrNotExist) {
			return b, err
		}
		if err = holders[owner].PullStaged(ctx, holders[1-owner], ref); err != nil {
			return nil, err
		}
		return holders[owner].Read(ctx, ref)
	}
	// Reusing a cached version reads its encrypted descriptor parts. Confirm
	// those parts on the new route before the catalog can reference them.
	if s.recoverRoute {
		if err := s.Check(ctx, ref); err != nil {
			return nil, err
		}
	}
	return s.Client.Read(ctx, ref)
}

// RecoverSealed imports the exact closure before submitting a migrated
// catalog. Neither the source view nor a new catalog signature is needed.
func (s *parallelSink) RecoverSealed(ctx context.Context, refs []generation.Object) error {
	if !s.recoverRoute || s.split {
		return ErrInvalid
	}
	if err := s.Begin(ctx); err != nil {
		return err
	}
	for _, ref := range refs {
		if err := s.Check(ctx, filekit.Object{ID: ref.ID, Bytes: ref.Bytes}); err != nil {
			return err
		}
	}
	return nil
}

func (s *parallelSink) Check(ctx context.Context, ref filekit.Object) error {
	if s.split {
		holders := [2]*ingress.Client{s.Client, s.companion}
		owner := s.splitOwner(ref)
		err := holders[owner].Check(ctx, ref)
		if s.replaying && errors.Is(err, os.ErrNotExist) {
			// A previous source PUT may have completed before delivery to the
			// stable owner. Import the exact staged bytes before resending.
			return holders[owner].PullStaged(ctx, holders[1-owner], ref)
		}
		return err
	}
	primary, other := s.Client, s.companion
	err := primary.Check(ctx, ref)
	if err != nil && (!s.recoverRoute || !errors.Is(err, os.ErrNotExist)) {
		return err
	}
	otherErr := other.Check(ctx, ref)
	if err == nil && s.recoverRoute && errors.Is(otherErr, os.ErrNotExist) {
		return s.relayAcceptedStaged(ctx, other, primary, ref)
	}
	if errors.Is(err, os.ErrNotExist) && otherErr == nil {
		return s.relayAcceptedStaged(ctx, primary, other, ref)
	}
	return otherErr
}

func (s *parallelSink) Write(ctx context.Context, ref filekit.Object, payload []byte) (bool, error) {
	if s.split {
		if err := s.Check(ctx, ref); err == nil {
			return false, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		holders := [2]*ingress.Client{s.Client, s.companion}
		owner := s.splitOwner(ref)
		origin, debit := s.distribution.reservePreferred(ref.Bytes, owner)
		start := time.Now()
		created, err := holders[origin].Write(ctx, ref, payload)
		if origin != owner && errors.Is(err, statefile.ErrCapacity) {
			// The faster holder may be unable to stage this extra object.
			// Confirm the result before trying the stable owner directly.
			s.distribution.refund(debit)
			err = holders[owner].PullStaged(ctx, holders[origin], ref)
			if errors.Is(err, os.ErrNotExist) {
				return holders[owner].Write(ctx, ref, payload)
			}
			return false, err
		}
		if err != nil {
			return false, err
		}
		if created {
			s.distribution.observe(origin, ref.Bytes, time.Since(start))
		} else {
			s.distribution.refund(debit)
		}
		if origin != owner {
			if err = s.relayAcceptedStaged(ctx, holders[owner], holders[origin], ref); err != nil {
				return false, err
			}
		}
		return created, nil
	}
	holder, debit := s.distribution.reserve(ref.Bytes)
	sent := false
	defer func() {
		if !sent {
			s.distribution.refund(debit)
		}
	}()
	origin, destination := s.Client, s.companion
	if holder == 1 {
		origin, destination = destination, origin
	}
	e := origin.Check(ctx, ref)
	if e == nil {
		return false, s.relayAcceptedStaged(ctx, destination, origin, ref)
	}
	if !errors.Is(e, os.ErrNotExist) {
		return false, e
	}
	// After a restart the other holder may already have accepted this
	// exact ciphertext. Reuse it without asking the source to resend.
	if s.replaying {
		e = destination.Check(ctx, ref)
		if e == nil {
			return false, s.relayAcceptedStaged(ctx, origin, destination, ref)
		}
		if !errors.Is(e, os.ErrNotExist) {
			return false, e
		}
	}
	sent = true
	start := time.Now()
	created, e := origin.Write(ctx, ref, payload)
	if e != nil {
		return false, e
	}
	if created {
		s.distribution.observe(holder, ref.Bytes, time.Since(start))
	}
	if e = s.relayAcceptedStaged(ctx, destination, origin, ref); e != nil {
		return false, e
	}
	return created, nil
}

func (s *parallelSink) relayAcceptedStaged(ctx context.Context, destination, origin *ingress.Client, ref filekit.Object) error {
	err := destination.PullStaged(ctx, origin, ref)
	if ctx.Err() != nil || !errors.Is(err, ingress.ErrUnavailable) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	// A queue acknowledgement does not confirm delivery. Keep the original
	// transfer result and let the normal capture retry check both copies.
	if s.alternate != nil {
		probe, cancel := context.WithTimeout(ctx, time.Second)
		confirmed := s.alternate.Check(probe, ref) == nil
		cancel()
		if confirmed && destination.QueueStagedWithFallback(ctx, origin, s.alternate, ref) == nil {
			return err
		}
	}
	// A withdrawn alternate or an older receiver can still accept the primary.
	_ = destination.QueueStaged(ctx, origin, ref)
	return err
}

func (s *parallelSink) loadReceipt(generation string) (ingress.Receipt, error) {
	var record companionReceipt
	raw, e := s.records.Read("companion-receipt.json")
	if e != nil {
		return record.Receipt, e
	}
	if storage.Decode(raw, &record, ingress.MaxReceiptDocument+1024) != nil || record.Format != companionReceiptFormat || record.Intent != s.binding {
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
	r := record.Receipt
	if r.Generation != generation || !s.companion.ValidReceipt(r) {
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
	if err := s.saveCompanionReceipt(*other.receipt); err != nil {
		return progress, nil, errors.Join(e, err)
	}
	return progress, primary, e
}

func (s *parallelSink) saveCompanionReceipt(r ingress.Receipt) error {
	record := companionReceipt{Format: companionReceiptFormat, Intent: s.binding, Receipt: r}
	payload, _ := json.Marshal(record)
	record.Signature = ed25519.Sign(s.writer, payload)
	raw, _ := json.Marshal(record)
	return s.records.Write("companion-receipt.json", raw)
}

func (s *parallelSink) SettlementReceipt(ctx context.Context) (ingress.Receipt, error) {
	receipt, e := s.Client.SettlementReceipt(ctx)
	if e != nil {
		return ingress.Receipt{}, e
	}
	known, e := s.loadReceipt(receipt.Generation)
	if e == nil && !s.settling {
		return receipt, nil
	}
	if e != nil && (!errors.Is(e, os.ErrNotExist) || !s.settling) {
		return ingress.Receipt{}, e
	}
	other, err := s.companion.SettlementReceipt(ctx)
	if err != nil {
		return ingress.Receipt{}, err
	}
	if other.Generation != receipt.Generation || e == nil && known != other {
		return ingress.Receipt{}, ErrInvalid
	}
	if e != nil {
		if err = s.saveCompanionReceipt(other); err != nil {
			return ingress.Receipt{}, err
		}
	}
	return receipt, nil
}

func (s *parallelSink) settlementCopies(ctx context.Context, id string) ([]capture.CopyReceipt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	receipt, err := s.loadReceipt(id)
	if err != nil {
		return nil, err
	}
	raw, err := s.records.Read("companion-receipt.json")
	if err != nil {
		return nil, err
	}
	return []capture.CopyReceipt{{Target: receipt.Ingress, Generation: id, Verification: "ciphertext-readback",
		ObservedUnix: receipt.VerifiedAt, SignedObservation: string(raw)}}, nil
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
