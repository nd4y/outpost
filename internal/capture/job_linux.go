// Package capture coordinates one private, restartable source operation. The
// caller supplies installed provider and authenticated transport implementations.
package capture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/ingress"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/source"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const Format = "outpost-source-job-1"
const maxPlan = 32 << 20

var ErrInvalid = errors.New("invalid source job")
var ErrCopies = errors.New("required complete copies unavailable")

// Provider.Open must verify the exact previously acquired view. Release must be
// idempotent by operation/view, and must not delete or release another view.
// It is a local installed implementation, never executable remote job text.
type Provider interface {
	Open(context.Context, string) (*os.Root, error)
	Release(context.Context, string, string) error
}
type Sink interface {
	filekit.ObjectBackend
	Begin(context.Context) error
	FinishStep(context.Context, []byte) (generation.BatchResult, *ingress.Receipt, error)
	AcknowledgeStep(context.Context, ingress.Receipt) (ingress.Acknowledgement, error)
}
type Profile struct {
	ID             string           `json:"id"`
	Origin         string           `json:"origin"`
	View           string           `json:"view"`
	Consistency    string           `json:"consistency"`
	Selection      source.Selection `json:"selection"`
	MaxSourceBytes int64            `json:"maxSourceBytes"`
	ReleasePolicy  string           `json:"releasePolicy,omitempty"`
	MinimumCopies  int              `json:"minimumCopies"`
	CopyTargets    []string         `json:"copyTargets"`
}

// CopyReceipt is an observation from a locally installed authenticated verifier.
// A caller must not construct it from an unverified shared JSON job or callback.
type CopyReceipt struct {
	Target            string `json:"target"`
	Generation        string `json:"generation"`
	Verification      string `json:"verification"`
	ObservedUnix      int64  `json:"observedUnix"`
	SignedObservation string `json:"signedObservation,omitempty"`
}
type Options struct {
	Parent     *os.Root
	Directory  string
	Initialize bool
	// ReadOnly permits inspecting authenticated expired local history only.
	ReadOnly bool
	// Settlement is a fresh, exact receipt-only capability, never an intent renewal.
	Settlement        []byte
	Profile           Profile
	Authority, Intent []byte
	Owner             ed25519.PublicKey
	Data              filekit.Owner
	Writer            ed25519.PrivateKey
	Provider          Provider
	Sink              Sink
	// Cache persists encrypted version envelopes across jobs. Its admission and
	// backend must be configured by the local coordinator for this exact intent.
	Cache     *filekit.Store
	Previous  map[string]string
	Copies    func(context.Context, string) ([]CopyReceipt, error)
	Admission func(string) statefile.Admission
	Guard     func(context.Context) error
}
type filePlan struct {
	Entry           source.Entry `json:"entry"`
	File            string       `json:"file"`
	Previous        string       `json:"previous,omitempty"`
	ReliableLineage bool         `json:"reliableLineage"`
}
type privatePlan struct {
	Profile Profile     `json:"profile"`
	Source  source.Plan `json:"source"`
	Files   []filePlan  `json:"files"`
}
type State struct {
	Format         string           `json:"format"`
	Binding        string           `json:"binding"`
	Plan           string           `json:"plan"`
	Phase          string           `json:"phase"`
	StagedRelease  string           `json:"stagedRelease,omitempty"`
	CompletedFiles int              `json:"completedFiles"`
	ObservedUnix   int64            `json:"observedUnix"`
	Generation     string           `json:"generation,omitempty"`
	Receipt        *ingress.Receipt `json:"receipt,omitempty"`
	Copies         []CopyReceipt    `json:"copies,omitempty"`
}
type fileReceipt struct {
	Plan      string        `json:"plan"`
	Stats     filekit.Stats `json:"stats"`
	Signature []byte        `json:"signature,omitempty"`
}
type Checkpoint struct {
	Format     string          `json:"format"`
	Operation  string          `json:"operation"`
	Profile    string          `json:"profile"`
	View       string          `json:"view"`
	Domain     string          `json:"domain"`
	Repository string          `json:"repository"`
	Epoch      uint64          `json:"epoch"`
	Sequence   uint64          `json:"sequence"`
	Generation string          `json:"generation"`
	Receipt    ingress.Receipt `json:"receipt"`
	Copies     []CopyReceipt   `json:"copies"`
	Signature  []byte          `json:"signature,omitempty"`
}
type Job struct {
	root                *os.Root
	state, lease, files *statefile.Store
	options             Options
	intent              ingress.Intent
	authority           ingress.Authority
	binding             string
	plan                privatePlan
	Fault               func(string) error
	poisoned            bool
}

func phase(p string) int {
	for i, name := range []string{"PLANNED", "CAPTURING", "SEALED", "WAITING_COPIES", "CHECKPOINTED", "RELEASING", "RELEASED", "ACKNOWLEDGING", "COMPLETE"} {
		if name == p {
			return i
		}
	}
	return -1
}
func Open(ctx context.Context, o Options) (*Job, error) {
	if (o.ReadOnly || len(o.Settlement) != 0) && o.Initialize || o.ReadOnly && len(o.Settlement) != 0 {
		return nil, ErrInvalid
	}
	if len(o.Settlement) != 0 {
		if _, e := ingress.VerifySettlement(o.Settlement, o.Authority, o.Intent, o.Owner, time.Now()); e != nil {
			return nil, e
		}
	}
	i, a, e := ingress.VerifyIntent(o.Intent, o.Authority, o.Owner, time.Now())
	currentError := e
	if e != nil {
		if o.Initialize || storage.Decode(o.Intent, &i, ingress.MaxDocument) != nil {
			return nil, e
		}
		i, a, e = ingress.VerifyIntent(o.Intent, o.Authority, o.Owner, time.Unix(i.NotBefore, 0))
		if e != nil {
			return nil, e
		}
	}
	p := o.Profile
	if provider, ok := o.Provider.(VerifyingProvider); ok && p.Consistency != provider.Consistency() {
		return nil, ErrInvalid
	}
	if p.ID != a.Profile || !storage.ID(p.Origin) || !storage.ID(p.View) || p.MaxSourceBytes < 1 || p.MaxSourceBytes > 1<<60 || (p.Consistency != "best-effort" && p.Consistency != "filesystem" && p.Consistency != "application") || p.MinimumCopies < 1 || p.MinimumCopies > 2 || len(p.CopyTargets) > 128 || o.Provider == nil || o.Sink == nil || o.Cache == nil || o.Cache.Owner.Domain != i.Domain || o.Data.Domain != i.Domain || len(o.Data.Master) != 32 || len(o.Writer) != 64 || !bytes.Equal(o.Writer.Public().(ed25519.PublicKey), a.Trust.Writer) || len(o.Previous) > generation.MaxKits {
		return nil, ErrInvalid
	}
	seen := map[string]bool{}
	for _, id := range p.CopyTargets {
		if !storage.ID(id) || seen[id] || id == i.Source {
			return nil, ErrInvalid
		}
		seen[id] = true
	}
	if !seen[i.Ingress] || p.MinimumCopies > len(seen) || p.MinimumCopies > 1 && o.Copies == nil || !bytes.Equal(o.Data.Master, o.Cache.Owner.Master) || !bytes.Equal(o.Data.VerifyKey, o.Cache.Owner.VerifyKey) {
		return nil, ErrInvalid
	}
	switch p.ReleasePolicy {
	case "":
	case TwoHolderCoverage:
		sink, ok := o.Sink.(coverageSink)
		if !ok || p.MinimumCopies != 2 || len(seen) != 2 {
			return nil, ErrInvalid
		}
		bindings := sink.CoverageBindings()
		if len(bindings) != 2 || bindings[i.Ingress] != storage.Hash(o.Intent) {
			return nil, ErrInvalid
		}
		for id, binding := range bindings {
			if !seen[id] || !storage.ID(binding) {
				return nil, ErrInvalid
			}
		}
	default:
		return nil, ErrInvalid
	}
	for file, version := range o.Previous {
		if !storage.ID(file) || !storage.ID(version) {
			return nil, ErrInvalid
		}
	}
	if o.Guard != nil {
		if e = o.Guard(ctx); e != nil {
			return nil, e
		}
	}
	raw, _ := json.Marshal(struct {
		Profile           Profile
		Authority, Intent []byte
		Previous          map[string]string
	}{p, o.Authority, o.Intent, o.Previous})
	j := &Job{options: o, intent: i, authority: a, binding: storage.Hash(raw)}
	// Freeze caller-owned slices/maps through their private JSON contract.
	var frozen struct {
		Profile           Profile
		Authority, Intent []byte
		Previous          map[string]string
	}
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrInvalid
	}
	j.options.Profile = frozen.Profile
	j.options.Authority = frozen.Authority
	j.options.Intent = frozen.Intent
	j.options.Previous = frozen.Previous
	j.options.Owner = bytes.Clone(o.Owner)
	j.options.Settlement = bytes.Clone(o.Settlement)
	j.options.Writer = bytes.Clone(o.Writer)
	j.options.Data.Master = bytes.Clone(o.Data.Master)
	j.root, e = localfs.Directory(o.Parent, o.Directory, o.Initialize)
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*Job, error) { j.Close(); return nil, e }
	j.lease, e = statefile.OpenAt(j.root, "lease", 4096, o.Initialize)
	if e != nil {
		return fail(e)
	}
	j.state, e = statefile.OpenAt(j.root, "state", maxPlan, o.Initialize)
	if e != nil {
		return fail(e)
	}
	j.files, e = statefile.OpenAt(j.root, "files", 65536, o.Initialize)
	if e != nil {
		return fail(e)
	}
	j.state.Admit = j.admission("state")
	j.files.Admit = j.admission("files")
	e = j.lease.WithLock(ctx, func() error {
		raw, e := j.state.Read("job.json")
		if errors.Is(e, os.ErrNotExist) && o.Initialize {
			return j.prepare(ctx)
		}
		if e != nil {
			return e
		}
		s, e := j.decodeState(raw)
		if e != nil {
			return e
		}
		b, e := j.state.Read("plan.json")
		if e != nil {
			return e
		}
		if storage.Hash(b) != s.Plan || storage.Decode(b, &j.plan, maxPlan) != nil {
			return ErrInvalid
		}
		if len(j.plan.Files) > generation.MaxKits || len(j.plan.Files) == 0 || s.CompletedFiles > len(j.plan.Files) {
			return ErrInvalid
		}
		if phase(s.Phase) >= phase("SEALED") && s.CompletedFiles != len(j.plan.Files) {
			return ErrInvalid
		}
		if len(o.Settlement) != 0 {
			if e = j.settlementState(s); e != nil {
				return e
			}
		}
		if s.StagedRelease != "" {
			if e = j.validateStagedRelease(s); e != nil {
				return e
			}
		}
		if currentError != nil && !o.ReadOnly && len(o.Settlement) == 0 && phase(s.Phase) < phase("CHECKPOINTED") {
			return currentError
		}
		if phase(s.Phase) >= phase("CHECKPOINTED") {
			return j.validateCheckpoint(s)
		}
		return nil
	})
	if e != nil {
		return fail(e)
	}
	return j, nil
}
func (j *Job) admission(prefix string) statefile.Admission {
	return func(name string, size int) (func(bool) error, error) {
		if j.options.ReadOnly {
			return nil, ErrInvalid
		}
		if e := j.guard(context.Background()); e != nil {
			return nil, e
		}
		if j.options.Admission == nil {
			return func(bool) error { return j.guard(context.Background()) }, nil
		}
		finish, e := j.options.Admission(prefix)(name, size)
		if e != nil {
			return nil, e
		}
		return func(done bool) error { return errors.Join(finish(done), j.guard(context.Background())) }, nil
	}
}
func (j *Job) guard(ctx context.Context) error {
	if j.poisoned {
		return ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if len(j.options.Settlement) != 0 {
		if _, e := ingress.VerifySettlement(j.options.Settlement, j.options.Authority, j.options.Intent, j.options.Owner, time.Now()); e != nil {
			return e
		}
	}
	if j.options.Guard != nil {
		return j.options.Guard(ctx)
	}
	return nil
}
func (j *Job) point(name string) error {
	if j.Fault != nil {
		return j.Fault(name)
	}
	return nil
}
func (j *Job) Close() error {
	var e error
	for _, s := range []*statefile.Store{j.state, j.files, j.lease} {
		if s != nil {
			e = errors.Join(e, s.Close())
		}
	}
	if j.root != nil {
		e = errors.Join(e, j.root.Close())
	}
	return e
}
func (j *Job) decodeState(raw []byte) (State, error) {
	var s State
	if storage.Decode(raw, &s, maxPlan) != nil || s.Format != Format || s.Binding != j.binding || !storage.ID(s.Plan) || phase(s.Phase) < 0 || s.ObservedUnix < 1 || s.ObservedUnix > time.Now().Unix() || s.CompletedFiles < 0 || s.CompletedFiles > generation.MaxKits {
		return s, ErrInvalid
	}
	if s.StagedRelease != "" && (j.options.Profile.ReleasePolicy != TwoHolderCoverage ||
		phase(s.Phase) < phase("SEALED") ||
		s.StagedRelease != "CHECKPOINTED" && s.StagedRelease != "RELEASING" && s.StagedRelease != "RELEASED" ||
		phase(s.Phase) >= phase("RELEASED") && s.StagedRelease != "RELEASED") {
		return s, ErrInvalid
	}
	if phase(s.Phase) >= phase("SEALED") && !storage.ID(s.Generation) {
		return s, ErrInvalid
	}
	if phase(s.Phase) >= phase("WAITING_COPIES") && (s.Receipt == nil || s.Receipt.Generation != s.Generation || s.Receipt.Operation != j.intent.Operation) {
		return s, ErrInvalid
	}
	return s, nil
}
func (j *Job) save(s *State) error {
	now := time.Now().Unix()
	if now < s.ObservedUnix {
		return ErrInvalid
	}
	s.ObservedUnix = now
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	e = j.state.Write("job.json", raw)
	if e != nil {
		j.poisoned = true
	}
	return e
}
func (j *Job) Status(ctx context.Context) (State, error) {
	var s State
	e := j.state.WithLock(ctx, func() error {
		b, e := j.state.Read("job.json")
		if e != nil {
			return e
		}
		s, e = j.decodeState(b)
		return e
	})
	return s, e
}
func (j *Job) prepare(ctx context.Context) error {
	root, e := j.options.Provider.Open(ctx, j.options.Profile.View)
	if e != nil {
		return e
	}
	defer root.Close()
	plan, e := source.Scan(ctx, root, j.options.Profile.Selection)
	if e != nil {
		return e
	}
	if plan.SourceBytes > j.options.Profile.MaxSourceBytes {
		return statefile.ErrCapacity
	}
	j.plan = privatePlan{Profile: j.options.Profile, Source: plan}
	for _, entry := range plan.Entries {
		if entry.Domain != j.intent.Domain {
			continue
		}
		var raw []byte
		known := false
		if provider, ok := j.options.Provider.(LogicalProvider); ok {
			var logical []byte
			logical, known, e = provider.Lineage(entry)
			if e != nil {
				return e
			}
			if known {
				if len(logical) == 0 || len(logical) > 8192 {
					return ErrInvalid
				}
				raw, _ = json.Marshal(struct {
					Origin, Domain string
					Logical        []byte
				}{j.options.Profile.Origin, entry.Domain, logical})
			}
		}
		if !known {
			sec, ns, found, err := filekit.Birth(root, entry.Names[0], entry.Identity)
			if err != nil {
				return err
			}
			known = found
			if known {
				raw, _ = json.Marshal(struct {
					Origin, Domain string
					Device, Inode  uint64
					Birth          int64
					NS             uint32
				}{j.options.Profile.Origin, entry.Domain, entry.Identity.Device, entry.Identity.Inode, sec, ns})
			}
		}
		var id string
		if known {
			mac := hmac.New(sha256.New, j.options.Data.Master)
			mac.Write([]byte("outpost-source-lineage-1\x00"))
			mac.Write(raw)
			id = hex.EncodeToString(mac.Sum(nil))
		} else {
			var nonce [32]byte
			if _, e = rand.Read(nonce[:]); e != nil {
				return e
			}
			id = hex.EncodeToString(nonce[:])
		}
		j.plan.Files = append(j.plan.Files, filePlan{Entry: entry, File: id, Previous: j.options.Previous[id], ReliableLineage: known})
	}
	if len(j.plan.Files) < 1 || len(j.plan.Files) > generation.MaxKits {
		return statefile.ErrCapacity
	}
	if e = plan.Recheck(ctx, root); e != nil {
		return e
	}
	if provider, ok := j.options.Provider.(VerifyingProvider); ok {
		if e = provider.Validate(ctx, j.options.Profile.View, root, plan, j.intent.Domain); e != nil {
			return e
		}
	}
	raw, e := json.Marshal(j.plan)
	if e != nil || len(raw) > maxPlan {
		return statefile.ErrCapacity
	}
	if e = j.state.Write("plan.json", raw); e != nil {
		return e
	}
	s := State{Format: Format, Binding: j.binding, Plan: storage.Hash(raw), Phase: "PLANNED"}
	return j.save(&s)
}

// Run holds the operation lease. After SEALED it never reopens the source view.
// A failed provider release stays RELEASING and is retried before any ack.
func (j *Job) Run(ctx context.Context) error {
	if j.options.ReadOnly {
		return ErrInvalid
	}
	if len(j.options.Settlement) != 0 {
		g, e := ingress.VerifySettlement(j.options.Settlement, j.options.Authority, j.options.Intent, j.options.Owner, time.Now())
		if e != nil {
			return e
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Unix(g.ExpiresUnix, 0))
		defer cancel()
	}
	return j.lease.WithLock(ctx, func() error {
		if e := j.guard(ctx); e != nil {
			return e
		}
		s, e := j.Status(ctx)
		if e != nil {
			return e
		}
		if len(j.options.Settlement) != 0 {
			if e = j.settlementState(s); e != nil {
				return e
			}
		}
		if s.Phase == "COMPLETE" {
			return nil
		}
		if len(j.options.Settlement) != 0 && phase(s.Phase) < phase("CHECKPOINTED") {
			if e = j.settleReceipt(ctx, &s); e != nil {
				return e
			}
		}
		if len(j.options.Settlement) == 0 && phase(s.Phase) < phase("CHECKPOINTED") {
			if _, _, e = ingress.VerifyIntent(j.options.Intent, j.options.Authority, j.options.Owner, time.Now()); e != nil {
				return e
			}
		}
		if phase(s.Phase) < phase("SEALED") {
			if e = j.options.Sink.Begin(ctx); e != nil {
				return e
			}
			root, e := j.options.Provider.Open(ctx, j.options.Profile.View)
			if e != nil {
				return e
			}
			e = j.capture(ctx, root, &s)
			root.Close()
			if e != nil {
				return e
			}
		}
		if s.Phase == "SEALED" {
			raw, e := j.state.Read("catalog.json")
			if e != nil {
				return e
			}
			if storage.Hash(raw) != s.Generation {
				return ErrInvalid
			}
			if j.options.Profile.ReleasePolicy == TwoHolderCoverage {
				if e = j.releaseWithCoverage(ctx, &s, raw); e != nil {
					return e
				}
			}
			for {
				if e = j.guard(ctx); e != nil {
					return e
				}
				_, receipt, e := j.options.Sink.FinishStep(ctx, raw)
				if e != nil {
					return e
				}
				if receipt == nil {
					continue
				}
				if receipt.Operation != j.intent.Operation || receipt.Ingress != j.intent.Ingress || receipt.Generation != s.Generation || receipt.Domain != j.intent.Domain || receipt.Tenant != j.intent.Tenant || receipt.VerifiedAt < j.intent.NotBefore || receipt.VerifiedAt > time.Now().Unix() {
					return ErrInvalid
				}
				s.Receipt = receipt
				s.Phase = "WAITING_COPIES"
				if e = j.save(&s); e != nil {
					return e
				}
				if e = j.point("source-receipt-durable"); e != nil {
					return e
				}
				break
			}
		}
		if s.Phase == "WAITING_COPIES" {
			copies := []CopyReceipt{{Target: j.intent.Ingress, Generation: s.Generation, Verification: "ciphertext-readback", ObservedUnix: s.Receipt.VerifiedAt}}
			if j.options.Copies != nil {
				other, e := j.options.Copies(ctx, s.Generation)
				if e != nil {
					return e
				}
				copies = append(copies, other...)
			}
			accepted, e := j.verifyCopies(copies, s.Generation)
			if e != nil {
				return e
			}
			if len(accepted) < j.options.Profile.MinimumCopies {
				return ErrCopies
			}
			s.Copies = accepted
			checkpoint := Checkpoint{Format: Format, Operation: j.intent.Operation, Profile: j.intent.Profile, View: j.options.Profile.View, Domain: j.intent.Domain, Repository: j.intent.Repository, Epoch: j.intent.Epoch, Sequence: j.intent.Sequence, Generation: s.Generation, Receipt: *s.Receipt, Copies: s.Copies}
			raw, _ := json.Marshal(checkpoint)
			checkpoint.Signature = ed25519.Sign(j.options.Writer, raw)
			raw, _ = json.Marshal(checkpoint)
			if e = j.state.Write("checkpoint.json", raw); e != nil {
				return e
			}
			s.Phase = "CHECKPOINTED"
			if e = j.save(&s); e != nil {
				return e
			}
			if e = j.point("source-checkpoint-durable"); e != nil {
				return e
			}
		}
		if phase(s.Phase) >= phase("CHECKPOINTED") {
			if e = j.validateCheckpoint(s); e != nil {
				return e
			}
		}
		if s.Phase == "CHECKPOINTED" {
			s.Phase = "RELEASING"
			if e = j.save(&s); e != nil {
				return e
			}
			if e = j.point("source-release-intent-durable"); e != nil {
				return e
			}
		}
		if s.Phase == "RELEASING" {
			if s.StagedRelease != "RELEASED" {
				if e = j.options.Provider.Release(ctx, j.intent.Operation, j.options.Profile.View); e != nil {
					return e
				}
				if e = j.point("source-provider-released"); e != nil {
					return e
				}
			}
			if s.StagedRelease != "" {
				s.StagedRelease = "RELEASED"
			}
			s.Phase = "RELEASED"
			if e = j.save(&s); e != nil {
				return e
			}
			if e = j.point("source-released-durable"); e != nil {
				return e
			}
		}
		if s.Phase == "RELEASED" {
			s.Phase = "ACKNOWLEDGING"
			if e = j.save(&s); e != nil {
				return e
			}
		}
		if s.Phase == "ACKNOWLEDGING" {
			for {
				if e = j.guard(ctx); e != nil {
					return e
				}
				ack, e := j.options.Sink.AcknowledgeStep(ctx, *s.Receipt)
				if e != nil {
					return e
				}
				if ack.Receipt != *s.Receipt {
					return ErrInvalid
				}
				if ack.Clean {
					break
				}
			}
			if e = j.point("source-acknowledged"); e != nil {
				return e
			}
			for _, file := range j.plan.Files {
				if e = j.options.Cache.DiscardCaptureProgress(ctx, j.intent.Operation, file.File); e != nil {
					return e
				}
			}
			s.Phase = "COMPLETE"
			if e = j.save(&s); e != nil {
				return e
			}
			return j.point("source-complete-durable")
		}
		return nil
	})
}
func VerifyCheckpoint(raw []byte, trust generation.Trust) (Checkpoint, error) {
	var c Checkpoint
	if storage.Decode(raw, &c, 65536) != nil || c.Format != Format || c.Domain != trust.Domain || c.Repository != trust.Repository || c.Epoch != trust.Epoch || c.Sequence == 0 || !storage.ID(c.Operation) || !storage.ID(c.Profile) || !storage.ID(c.View) || !storage.ID(c.Generation) || c.Generation != c.Receipt.Generation || c.Operation != c.Receipt.Operation || len(c.Copies) < 1 || len(c.Copies) > 128 || len(trust.Writer) != 32 {
		return c, ErrInvalid
	}
	canonical, _ := json.Marshal(c)
	if !bytes.Equal(raw, canonical) {
		return c, ErrInvalid
	}
	signature := c.Signature
	c.Signature = nil
	payload, _ := json.Marshal(c)
	c.Signature = signature
	if !ed25519.Verify(trust.Writer, payload, signature) {
		return c, ErrInvalid
	}
	return c, nil
}
func (j *Job) validateCheckpoint(s State) error {
	raw, e := j.state.Read("checkpoint.json")
	if e != nil {
		return e
	}
	c, e := VerifyCheckpoint(raw, j.authority.Trust)
	if e != nil {
		return e
	}
	if c.Operation != j.intent.Operation || c.Profile != j.intent.Profile || c.View != j.options.Profile.View || c.Sequence != j.intent.Sequence || c.Generation != s.Generation || s.Receipt == nil || c.Receipt != *s.Receipt {
		return ErrInvalid
	}
	copies, e := j.verifyCopies(c.Copies, c.Generation)
	if e != nil || len(copies) < j.options.Profile.MinimumCopies {
		return ErrInvalid
	}
	a, _ := json.Marshal(copies)
	b, _ := json.Marshal(s.Copies)
	if !bytes.Equal(a, b) {
		return ErrInvalid
	}
	return nil
}
func (j *Job) verifyCopies(copies []CopyReceipt, generationID string) ([]CopyReceipt, error) {
	allowed := map[string]bool{}
	for _, id := range j.options.Profile.CopyTargets {
		allowed[id] = true
	}
	unique := map[string]CopyReceipt{}
	for _, r := range copies {
		if !allowed[r.Target] || r.Generation != generationID || r.Verification != "ciphertext-readback" || r.ObservedUnix < j.intent.SnapshotUnix || r.ObservedUnix > time.Now().Unix() || len(r.SignedObservation) > 16<<10 {
			return nil, ErrInvalid
		}
		if old, ok := unique[r.Target]; ok && old != r {
			return nil, ErrInvalid
		}
		unique[r.Target] = r
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]CopyReceipt, 0, len(ids))
	for _, id := range ids {
		out = append(out, unique[id])
	}
	return out, nil
}
func (j *Job) capture(ctx context.Context, root *os.Root, s *State) error {
	if e := j.plan.Source.Recheck(ctx, root); e != nil {
		return e
	}
	s.Phase = "CAPTURING"
	if e := j.save(s); e != nil {
		return e
	}
	versions := make([]string, 0, len(j.plan.Files))
	for index, file := range j.plan.Files {
		if e := j.guard(ctx); e != nil {
			return e
		}
		var result filekit.Stats
		raw, e := j.files.Read(file.File)
		if errors.Is(e, os.ErrNotExist) {
			if index < s.CompletedFiles {
				return ErrInvalid
			}
			result, e = j.plan.Source.CaptureEntryProgress(ctx, root, file.Entry, j.options.Cache, file.File, file.Previous, j.intent.Operation)
			if e != nil {
				return e
			}
			receipt := fileReceipt{Plan: s.Plan, Stats: result}
			raw, e = json.Marshal(receipt)
			if e != nil {
				return e
			}
			receipt.Signature = ed25519.Sign(j.options.Writer, raw)
			raw, e = json.Marshal(receipt)
			if e != nil {
				return e
			}
			if e = j.files.Write(file.File, raw); e != nil {
				return e
			}
			if e = j.point("source-file-durable"); e != nil {
				return e
			}
		} else if e != nil {
			return e
		} else {
			var receipt fileReceipt
			if storage.Decode(raw, &receipt, 65536) != nil || receipt.Plan != s.Plan {
				return ErrInvalid
			}
			canonical, _ := json.Marshal(receipt)
			if !bytes.Equal(raw, canonical) {
				return ErrInvalid
			}
			signature := receipt.Signature
			receipt.Signature = nil
			payload, _ := json.Marshal(receipt)
			if !ed25519.Verify(j.authority.Trust.Writer, payload, signature) {
				return ErrInvalid
			}
			result = receipt.Stats
		}
		if result.File != file.File || !storage.ID(result.Version) {
			return ErrInvalid
		}
		versions = append(versions, result.Version)
		if index >= s.CompletedFiles {
			s.CompletedFiles = index + 1
			if e = j.save(s); e != nil {
				return e
			}
		}
	}
	if e := j.plan.Source.Recheck(ctx, root); e != nil {
		return e
	}
	i := j.intent
	raw, roots, e := generation.BuildCatalog(ctx, j.options.Cache, versions, generation.Catalog{Format: generation.Format, Domain: i.Domain, Repository: i.Repository, Epoch: i.Epoch, Sequence: i.Sequence, Parent: i.Parent, SnapshotUnix: i.SnapshotUnix, Policy: i.Policy}, j.options.Writer)
	if e != nil {
		return e
	}
	ids := make([]string, 0, len(roots))
	for id := range roots {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := roots[id]
		if _, e = j.options.Sink.Write(ctx, filekit.Object{ID: id, Bytes: len(b)}, b); e != nil {
			return e
		}
	}
	if e = j.plan.Source.Recheck(ctx, root); e != nil {
		return e
	}
	if provider, ok := j.options.Provider.(VerifyingProvider); ok {
		if e = provider.Validate(ctx, j.options.Profile.View, root, j.plan.Source, j.intent.Domain); e != nil {
			return e
		}
	}
	if e = j.state.Write("catalog.json", raw); e != nil {
		return e
	}
	s.Generation = storage.Hash(raw)
	s.Phase = "SEALED"
	if e = j.save(s); e != nil {
		return e
	}
	return j.point("source-catalog-durable")
}
