package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/localfs"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/volume"
	"golang.org/x/sys/unix"
)

const ProfileFormat = "outpost-trusted-recovery-1"
const ReceiptFormat = "outpost-recovery-result-1"
const maxOperations = 1024
const maxAttempts = 3

type Preset struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	Repository string `json:"repository"`
	Epoch      uint64 `json:"epoch"`
	OwnerFile  string `json:"ownerFile"`
}

// Profile is private local enrollment. It must never be accepted from a remote
// command, included in worker policy or sent to the management service.
type Profile struct {
	Format    string         `json:"format"`
	Node      string         `json:"node"`
	Directory string         `json:"directory"`
	Volume    volume.Binding `json:"volume"`
	Limits    Limits         `json:"limits"`
	Presets   []Preset       `json:"presets"`
}
type Request struct {
	Operation  string   `json:"operation"`
	Binding    string   `json:"binding"`
	Preset     string   `json:"preset"`
	Generation string   `json:"generation"`
	Versions   []string `json:"versions,omitempty"`
}
type Receipt struct {
	Format       string                     `json:"format"`
	Operation    string                     `json:"operation"`
	Binding      string                     `json:"binding"`
	Preset       string                     `json:"preset"`
	VerifiedUnix int64                      `json:"verifiedUnix"`
	Restored     generation.RecoveryReceipt `json:"restored"`
}
type operation struct {
	Format         string   `json:"format"`
	Scope          string   `json:"scope"`
	Request        Request  `json:"request"`
	Phase          string   `json:"phase"`
	Attempts       int      `json:"attempts"`
	Stage          string   `json:"stage"`
	PreparedDigest string   `json:"preparedDigest,omitempty"`
	Result         *Receipt `json:"result,omitempty"`
	Digest         string   `json:"digest"`
}
type Executor struct {
	profile   Profile
	scope     string
	root      *os.Root
	admission *Admission
	journal   *statefile.Store
	presets   map[string]Preset
	Fault     func(string) error
}

var ErrStopped = errors.New("recovery operation stopped")

func (x *Executor) NodeIdentity() string { return x.profile.Node }
func (x *Executor) PresetDomain(id, domain string) bool {
	p, ok := x.presets[id]
	return ok && p.Domain == domain
}
func (r Receipt) Validate() error {
	s := r.Restored.Restored
	if r.Format != ReceiptFormat || !storage.ID(r.Operation) || !storage.ID(r.Binding) || !storage.ID(r.Preset) || r.VerifiedUnix < 1 || r.VerifiedUnix > 1<<50 || !storage.ID(r.Restored.Generation) || r.Restored.Epoch == 0 || r.Restored.Epoch > (1<<53)-1 || r.Restored.Sequence == 0 || r.Restored.Sequence > (1<<53)-1 || !r.Restored.CheckpointMatch || s.Bytes < 0 || s.Bytes > 1<<58 {
		return ErrInvalid
	}
	total := 0
	for _, n := range []int{s.Files, s.Directories, s.Symlinks, s.Aliases, s.ImplicitDirectories} {
		if n < 0 || n > 32768 {
			return ErrInvalid
		}
		total += n
	}
	if total < 1 || total > 32768 {
		return ErrInvalid
	}
	return nil
}
func digest(v any) string { b, _ := json.Marshal(v); return storage.Hash(b) }

func OpenExecutor(ctx context.Context, p Profile, initialize bool) (*Executor, error) {
	if p.Format != ProfileFormat || !storage.ID(p.Node) || p.Volume.Scope != p.Node || !p.Limits.valid() || !filepath.IsAbs(p.Directory) || filepath.Clean(p.Directory) != p.Directory || len(p.Presets) == 0 || len(p.Presets) > 64 {
		return nil, ErrInvalid
	}
	presets := map[string]Preset{}
	for _, preset := range p.Presets {
		if !storage.ID(preset.ID) || !storage.ID(preset.Domain) || !storage.ID(preset.Repository) || preset.Epoch == 0 || !filepath.IsAbs(preset.OwnerFile) || filepath.Clean(preset.OwnerFile) != preset.OwnerFile {
			return nil, ErrInvalid
		}
		if _, ok := presets[preset.ID]; ok {
			return nil, ErrInvalid
		}
		presets[preset.ID] = preset
	}
	r, e := p.Volume.Open(ctx, p.Directory, initialize)
	if e != nil {
		return nil, e
	}
	x := &Executor{profile: p, scope: digest(p), root: r, presets: presets}
	success := false
	defer func() {
		if !success {
			x.Close()
		}
	}()
	x.admission, e = OpenAdmission(ctx, r, p.Limits, initialize, x.guard)
	if e != nil {
		return nil, e
	}
	x.journal, e = statefile.OpenAt(r, ".operations", 1<<20, initialize)
	if e != nil {
		return nil, e
	}
	e = x.admission.state.WithLock(ctx, func() error {
		if e := x.guard(ctx); e != nil {
			return e
		}
		if initialize {
			for _, name := range []string{"staging", "results"} {
				if e := r.Mkdir(name, 0700); e != nil {
					return e
				}
			}
			b, _ := json.Marshal(struct{ Format, Scope string }{ProfileFormat, x.scope})
			if e := x.journal.Write("profile.json", b); e != nil {
				return e
			}
			return syncRoot(r)
		}
		b, e := x.journal.Read("profile.json")
		if e != nil {
			return e
		}
		var saved struct{ Format, Scope string }
		if storage.Decode(b, &saved, 4096) != nil || saved.Format != ProfileFormat || saved.Scope != x.scope {
			return ErrConflict
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	success = true
	return x, nil
}
func (x *Executor) Close() error {
	var e error
	if x.journal != nil {
		e = errors.Join(e, x.journal.Close())
	}
	if x.admission != nil {
		e = errors.Join(e, x.admission.Close())
	}
	if x.root != nil {
		e = errors.Join(e, x.root.Close())
	}
	return e
}
func (x *Executor) guard(ctx context.Context) error {
	return x.profile.Volume.CheckHandle(ctx, x.profile.Directory, x.root)
}
func (x *Executor) point(name string) error {
	if x.Fault != nil {
		return x.Fault(name)
	}
	return nil
}
func (x *Executor) validate(r Request) (Preset, error) {
	p, ok := x.presets[r.Preset]
	if !ok || !storage.ID(r.Operation) || !storage.ID(r.Binding) || !storage.ID(r.Generation) || len(r.Versions) > 256 {
		return p, ErrInvalid
	}
	seen := map[string]bool{}
	for _, v := range r.Versions {
		if !storage.ID(v) || seen[v] {
			return p, ErrInvalid
		}
		seen[v] = true
	}
	return p, nil
}
func (x *Executor) load(r Request) (operation, error) {
	var op operation
	b, e := x.journal.Read("operation-" + r.Operation + ".json")
	if e != nil {
		return op, e
	}
	if storage.Decode(b, &op, 1<<20) != nil {
		return op, ErrInvalid
	}
	hash := op.Digest
	op.Digest = ""
	actual := digest(op)
	op.Digest = hash
	if !storage.ID(hash) || hash != actual || op.Format != ProfileFormat || op.Scope != x.scope || digest(op.Request) != digest(r) || op.Attempts < 1 || op.Attempts > maxAttempts || !storage.ID(op.Stage) {
		return op, ErrConflict
	}
	if op.Phase != "WRITING" && op.Phase != "PREPARED" && op.Phase != "COMPLETE" && op.Phase != "STOPPED" {
		return op, ErrInvalid
	}
	if op.Phase == "WRITING" || op.Phase == "STOPPED" {
		if op.Result != nil || op.PreparedDigest != "" {
			return op, ErrInvalid
		}
	} else {
		p := x.presets[r.Preset]
		if op.Result == nil || op.Result.Validate() != nil || !storage.ID(op.PreparedDigest) || digest(op.Result) != op.PreparedDigest || op.Result.Format != ReceiptFormat || op.Result.Operation != r.Operation || op.Result.Binding != r.Binding || op.Result.Preset != r.Preset || op.Result.VerifiedUnix < 1 || op.Result.Restored.Generation != r.Generation || op.Result.Restored.Epoch != p.Epoch || op.Result.Restored.Sequence == 0 || !op.Result.Restored.CheckpointMatch {
			return op, ErrInvalid
		}
	}
	return op, nil
}
func (x *Executor) save(op operation) error {
	op.Digest = ""
	op.Digest = digest(op)
	b, e := json.Marshal(op)
	if e != nil {
		return e
	}
	return x.journal.Write("operation-"+op.Request.Operation+".json", b)
}
func syncRoot(r *os.Root) error {
	f, e := r.Open(".")
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func nonce() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func pin(r Request) string {
	return storage.Hash([]byte("outpost-trusted-recovery-pin-1/" + r.Operation + "/" + r.Binding))
}
func (x *Executor) reservationBinding(r Request) string {
	return digest(struct {
		Scope   string
		Request Request
	}{x.scope, r})
}
func (x *Executor) releaseCompletedReservation(ctx context.Context, r Request) error {
	s, e := x.admission.load()
	if e != nil {
		return e
	}
	pending, exists := s.Pending[r.Operation]
	if !exists {
		return nil
	}
	if pending.Binding != x.reservationBinding(r) {
		return ErrConflict
	}
	if _, e = x.admission.measure(ctx); e != nil {
		return e
	}
	delete(s.Pending, r.Operation)
	return x.admission.save(s)
}

// Outcome returns an original historical receipt, not a fresh integrity check.
// After an interrupted final rename it reconciles only a bundle matching the
// already persisted prepared digest. An arbitrary existing directory is refused.
func (x *Executor) Outcome(ctx context.Context, r Request) (*Receipt, error) {
	if _, e := x.validate(r); e != nil {
		return nil, e
	}
	var out *Receipt
	e := x.admission.state.WithLock(ctx, func() error {
		if e := x.guard(ctx); e != nil {
			return e
		}
		op, e := x.load(r)
		if errors.Is(e, os.ErrNotExist) {
			if _, e = x.root.Lstat("results/" + r.Operation); !errors.Is(e, os.ErrNotExist) {
				return ErrConflict
			}
			return nil
		}
		if e != nil {
			return e
		}
		if op.Phase == "STOPPED" {
			return ErrStopped
		}
		out, e = x.completed(ctx, &op)
		return e
	})
	return out, e
}
func (x *Executor) completed(ctx context.Context, op *operation) (*Receipt, error) {
	if op.Phase == "COMPLETE" {
		return op.Result, x.releaseCompletedReservation(ctx, op.Request)
	}
	results, e := localfs.OpenAt(x.root, "results", false)
	if e != nil {
		return nil, e
	}
	defer results.Close()
	bundle, e := localfs.OpenAt(results, op.Request.Operation, false)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	defer bundle.Close()
	if op.Phase != "PREPARED" {
		return nil, ErrConflict
	}
	s, e := statefile.OpenAt(bundle, ".", 65536, false)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	raw, e := s.Read("receipt.json")
	if e != nil {
		return nil, e
	}
	if storage.Hash(raw) != op.PreparedDigest {
		return nil, ErrConflict
	}
	if e = x.guard(ctx); e != nil {
		return nil, e
	}
	op.Phase = "COMPLETE"
	if e = x.save(*op); e != nil {
		return nil, e
	}
	if e = x.point("recovery-result-durable"); e != nil {
		return nil, e
	}
	return op.Result, x.releaseCompletedReservation(ctx, op.Request)
}

func (x *Executor) Restore(ctx context.Context, r Request, source *generation.Replica, authorize func(context.Context) error) (Receipt, error) {
	return x.RestoreCommitted(ctx, r, source, authorize, func(ctx context.Context, publish func() error) error {
		if e := authorize(ctx); e != nil {
			return e
		}
		return publish()
	})
}

// RestoreCommitted allows a private executor to serialize final publication
// with withdrawal of the signed policy. The gate must invoke publish once.
func (x *Executor) RestoreCommitted(ctx context.Context, r Request, source *generation.Replica, authorize func(context.Context) error, commit func(context.Context, func() error) error) (Receipt, error) {
	var out Receipt
	p, e := x.validate(r)
	if e != nil || source == nil || authorize == nil || commit == nil {
		return out, ErrInvalid
	}
	trust := source.Trust()
	if trust.Domain != p.Domain || trust.Repository != p.Repository || trust.Epoch != p.Epoch {
		return out, ErrConflict
	}
	if prior, e := x.Outcome(ctx, r); e != nil {
		return out, e
	} else if prior != nil {
		return *prior, source.ReleasePin(ctx, pin(r))
	}
	check := func(ctx context.Context) error {
		if e := authorize(ctx); e != nil {
			return e
		}
		return x.guard(ctx)
	}
	if e = check(ctx); e != nil {
		return out, e
	}
	if e = source.CheckRecoveryDestination(ctx, x.root); e != nil {
		return out, e
	}
	owner, e := filekit.ReadOwner(p.OwnerFile)
	if e != nil {
		return out, e
	}
	owner.SigningKey = nil
	if owner.Domain != p.Domain {
		return out, ErrConflict
	}
	raw, e := source.Catalog(ctx, r.Generation)
	if e != nil {
		return out, e
	}
	selection := generation.RecoverySelection{Versions: r.Versions}
	fetch := func(ctx context.Context, o generation.Object) ([]byte, error) {
		if e := check(ctx); e != nil {
			return nil, e
		}
		return source.ReadObject(ctx, r.Generation, o)
	}
	plan, e := generation.PlanRecoveryCatalog(ctx, r.Generation, raw, trust, owner, selection, fetch)
	if e != nil {
		return out, e
	}
	entries := plan.Files + plan.Directories + plan.Symlinks + plan.Aliases + plan.ImplicitDirectories
	// Includes a second copy allowance, block/xattr overhead, temporary names,
	// bundle metadata and receipt writes. Retained earlier attempts are measured.
	if plan.Bytes < 0 || plan.Bytes > 1<<58 || entries < 1 || entries > 32768 {
		return out, ErrCapacity
	}
	estimate := Estimate{Bytes: 2*plan.Bytes + int64(entries)*65536 + 1<<20, Entries: entries + 16}
	e = x.admission.WithReservation(ctx, ReservationRequest{Operation: r.Operation, Binding: x.reservationBinding(r), Estimate: estimate}, func(lease *Lease) error {
		if e := check(ctx); e != nil {
			return e
		}
		op, e := x.load(r)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		if e == nil {
			if result, e := x.completed(ctx, &op); e != nil {
				return e
			} else if result != nil {
				out = *result
				return nil
			}
		} else {
			f, e := x.root.Open(".operations")
			if e != nil {
				return e
			}
			names, e := f.ReadDir(maxOperations + 8)
			f.Close()
			if e != nil && !errors.Is(e, io.EOF) {
				return e
			}
			operations := 0
			for _, name := range names {
				if strings.HasPrefix(name.Name(), "operation-") && strings.HasSuffix(name.Name(), ".json") {
					operations++
				}
			}
			if operations >= maxOperations || len(names) >= maxOperations+8 {
				return ErrCapacity
			}
			op = operation{Format: ProfileFormat, Scope: x.scope, Request: r}
		}
		if op.Phase == "STOPPED" {
			return ErrStopped
		}
		if op.Attempts >= maxAttempts {
			return ErrCapacity
		}
		stage, e := nonce()
		if e != nil {
			return e
		}
		op.Attempts++
		op.Stage = stage
		op.Phase = "WRITING"
		op.Result = nil
		op.PreparedDigest = ""
		if e = x.save(op); e != nil {
			return e
		}
		if e = x.point("recovery-intent-durable"); e != nil {
			return e
		}
		if e = source.Pin(ctx, pin(r), r.Generation, "restore"); e != nil {
			return e
		}
		if e = x.point("recovery-pin-durable"); e != nil {
			return e
		}
		stages, e := localfs.OpenAt(x.root, "staging", false)
		if e != nil {
			return e
		}
		defer stages.Close()
		if e = stages.Mkdir(stage, 0700); e != nil {
			return e
		}
		if e = syncRoot(stages); e != nil {
			return e
		}
		dest, e := localfs.OpenAt(stages, stage, false)
		if e != nil {
			return e
		}
		defer dest.Close()
		boundedFetch := func(ctx context.Context, o generation.Object) ([]byte, error) {
			if e := lease.Guard(ctx); e != nil {
				return nil, e
			}
			return fetch(ctx, o)
		}
		restored, e := generation.RecoverCatalogAt(ctx, r.Generation, raw, trust, owner, selection, boundedFetch, dest, "data")
		if e != nil {
			return e
		}
		if restored.Restored != plan {
			return ErrConflict
		}
		if e = x.point("recovery-data-durable"); e != nil {
			return e
		}
		out = Receipt{Format: ReceiptFormat, Operation: r.Operation, Binding: r.Binding, Preset: r.Preset, VerifiedUnix: time.Now().Unix(), Restored: restored}
		s, e := statefile.OpenAt(dest, ".", 65536, false)
		if e != nil {
			return e
		}
		body, _ := json.Marshal(out)
		e = s.Write("receipt.json", body)
		s.Close()
		if e != nil {
			return e
		}
		op.Result = &out
		op.PreparedDigest = storage.Hash(body)
		op.Phase = "PREPARED"
		if e = x.save(op); e != nil {
			return e
		}
		if e = x.point("recovery-prepared-durable"); e != nil {
			return e
		}
		if e = check(ctx); e != nil {
			return e
		}
		if e = lease.BeforePublish(ctx); e != nil {
			return e
		}
		results, e := localfs.OpenAt(x.root, "results", false)
		if e != nil {
			return e
		}
		defer results.Close()
		from, e := stages.Open(".")
		if e != nil {
			return e
		}
		defer from.Close()
		to, e := results.Open(".")
		if e != nil {
			return e
		}
		defer to.Close()
		if e = x.point("recovery-before-publish"); e != nil {
			return e
		}
		if e = check(ctx); e != nil {
			return e
		}
		published := false
		if e = commit(ctx, func() error {
			if published {
				return ErrConflict
			}
			if e := x.guard(ctx); e != nil {
				return e
			}
			if e := unix.Renameat2(int(from.Fd()), stage, int(to.Fd()), r.Operation, unix.RENAME_NOREPLACE); e != nil {
				return e
			}
			published = true
			if e := to.Sync(); e != nil {
				return e
			}
			return from.Sync()
		}); e != nil {
			return e
		}
		if !published {
			return ErrConflict
		}
		if e = x.point("recovery-bundle-durable"); e != nil {
			return e
		}
		completed, e := x.completed(ctx, &op)
		if e != nil {
			return e
		}
		if completed == nil {
			return ErrConflict
		}
		out = *completed
		return nil
	})
	if e != nil {
		return out, e
	}
	if e = x.point("recovery-before-pin-release"); e != nil {
		return out, e
	}
	return out, source.ReleasePin(ctx, pin(r))
}
