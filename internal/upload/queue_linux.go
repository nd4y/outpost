package upload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/nd4y/outpost/internal/localfs"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

const QueueFormat = "outpost-upload-queue-1"
const maxQueueBytes = 32 << 20

var ErrBlocked = errors.New("upload queue contains blocked or expired jobs")

type QueueLimits struct {
	MaxJobs         int `json:"maxJobs"`
	Parallel        int `json:"parallel"`
	AttemptMillis   int `json:"attemptMillis"`
	RetryBaseMillis int `json:"retryBaseMillis"`
	RetryMaxMillis  int `json:"retryMaxMillis"`
}

func (l QueueLimits) valid() bool {
	return l.MaxJobs >= 1 && l.MaxJobs <= 64 && l.Parallel >= 1 && l.Parallel <= 4 && l.AttemptMillis >= 100 && l.AttemptMillis <= 300000 && l.RetryBaseMillis >= 50 && l.RetryBaseMillis <= 60000 && l.RetryMaxMillis >= l.RetryBaseMillis && l.RetryMaxMillis <= 3600000
}

type QueueJob struct {
	Plan           json.RawMessage `json:"plan"`
	Phase          string          `json:"phase"`
	Attempts       uint64          `json:"attempts"`
	NextMillis     int64           `json:"nextMillis"`
	ErrorCode      string          `json:"errorCode,omitempty"`
	Receipt        *Receipt        `json:"receipt,omitempty"`
	CleanupPending bool            `json:"cleanupPending"`
}
type QueueState struct {
	Format   string              `json:"format"`
	Identity string              `json:"identity"`
	Instance string              `json:"instance"`
	Revision uint64              `json:"revision"`
	Jobs     map[string]QueueJob `json:"jobs"`
}
type Queue struct {
	root             *os.Root
	worker, identity string
	instance         string
	authority        Authority
	limits           QueueLimits
	// Fault is a development-test hook; production callers leave it nil.
	Fault func(string) error
	Admit statefile.Admission
}

// OpenQueue requires a caller-admitted persistent Linux directory. No credentials
// or worker private keys are serialized. Authority and resource bounds are pinned.
func OpenQueue(dir, worker string, a Authority, limits QueueLimits, initialize bool) (*Queue, error) {
	return OpenQueueAdmitted(dir, worker, a, limits, initialize, nil)
}
func OpenQueueAdmitted(dir, worker string, a Authority, limits QueueLimits, initialize bool, admit statefile.Admission) (*Queue, error) {
	return OpenQueueAt(nil, dir, worker, a, limits, initialize, admit)
}
func OpenQueueAt(parent *os.Root, dir, worker string, a Authority, limits QueueLimits, initialize bool, admit statefile.Admission) (*Queue, error) {
	if !storage.ID(worker) || !limits.valid() || len(a.Planner) != ed25519.PublicKeySize || !storage.ID(a.Generation.Domain) || !storage.ID(a.Generation.Repository) || a.Generation.Epoch == 0 || len(a.Generation.Writer) != ed25519.PublicKeySize || len(a.Generation.Maintenance) != ed25519.PublicKeySize || bytes.Equal(a.Generation.Writer, a.Generation.Maintenance) {
		return nil, ErrDenied
	}
	raw, _ := json.Marshal(struct {
		Worker    string
		Authority Authority
		Limits    QueueLimits
	}{worker, a, limits})
	a.Planner = append([]byte(nil), a.Planner...)
	a.Generation.Writer = append([]byte(nil), a.Generation.Writer...)
	a.Generation.Maintenance = append([]byte(nil), a.Generation.Maintenance...)
	r, e := localfs.Directory(parent, dir, false)
	if e != nil {
		return nil, e
	}
	q := &Queue{root: r, worker: worker, identity: storage.Hash(raw), authority: a, limits: limits, Admit: admit}
	if initialize {
		f, e := r.Open(".")
		if e != nil {
			r.Close()
			return nil, e
		}
		entries, e := f.ReadDir(1)
		f.Close()
		if len(entries) != 0 || e != io.EOF {
			r.Close()
			return nil, ErrDenied
		}
		var nonce [32]byte
		if _, e = rand.Read(nonce[:]); e != nil {
			r.Close()
			return nil, e
		}
		q.instance = storage.Hash(nonce[:])
		if e = q.save(QueueState{Format: QueueFormat, Identity: q.identity, Instance: q.instance, Jobs: map[string]QueueJob{}}); e != nil {
			r.Close()
			return nil, e
		}
	}
	s, e := q.load()
	if e != nil {
		r.Close()
		return nil, e
	}
	q.instance = s.Instance
	return q, nil
}
func (q *Queue) Close() error { return q.root.Close() }
func (q *Queue) checkpoint(point string) error {
	if q.Fault != nil {
		return q.Fault(point)
	}
	return nil
}
func (q *Queue) load() (QueueState, error) {
	var s QueueState
	raw, e := regular(q.root, "queue.json", maxQueueBytes)
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, maxQueueBytes) != nil || s.Format != QueueFormat || s.Identity != q.identity || !storage.ID(s.Instance) || q.instance != "" && s.Instance != q.instance || s.Jobs == nil || len(s.Jobs) > q.limits.MaxJobs {
		return s, ErrConflict
	}
	for op, j := range s.Jobs {
		p, e := Verify(j.Plan, q.authority)
		if e != nil || p.Operation != op {
			return s, ErrDenied
		}
		if _, ok := p.worker(q.worker); !ok {
			return s, ErrDenied
		}
		switch j.Phase {
		case "ADMITTING", "QUEUED", "RUNNING", "RETRY_WAIT", "BLOCKED", "EXPIRED", "COMPLETE":
		default:
			return s, ErrDenied
		}
		switch j.ErrorCode {
		case "", "UNAVAILABLE", "DEADLINE", "CANCELLED", "AUTH", "CAPACITY", "INTEGRITY", "CONFLICT", "UNSUPPORTED", "LOCAL", "EXPIRED":
		default:
			return s, ErrDenied
		}
		if j.NextMillis < 0 || j.NextMillis > p.ExpiresUnix*1000 || (j.Phase == "COMPLETE") != (j.Receipt != nil) || j.CleanupPending && j.Phase != "COMPLETE" {
			return s, ErrDenied
		}
		if j.Receipt != nil {
			r := j.Receipt
			if r.Target != p.Profile.ID() || r.Generation != p.Generation || r.Operation != op || r.Executor != q.worker || r.Verification != "full-target-readback" || r.ObservedUnix < 1 {
				return s, ErrDenied
			}
		}
	}
	return s, nil
}
func (q *Queue) save(s QueueState) error {
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	if len(raw) > maxQueueBytes {
		return storage.ErrCapacity
	}
	return statefile.Guard(q.Admit, "queue.json", len(raw), func() error { return atomicFile(q.root, "queue.json", raw) })
}
func (q *Queue) edit(ctx context.Context, fn func(*QueueState) error) error {
	unlock, e := lock(ctx, q.root, "queue.lock")
	if e != nil {
		return e
	}
	defer unlock()
	s, e := q.load()
	if e != nil {
		return e
	}
	if e = fn(&s); e != nil {
		return e
	}
	if s.Revision == ^uint64(0) {
		return storage.ErrCapacity
	}
	s.Revision++
	return q.save(s)
}
func (q *Queue) Status(ctx context.Context) (QueueState, error) {
	unlock, e := lock(ctx, q.root, "queue.lock")
	if e != nil {
		return QueueState{}, e
	}
	defer unlock()
	return q.load()
}
func (q *Queue) pin(op string) string {
	return storage.Hash([]byte(QueueFormat + "/pin/" + q.instance + "/" + q.worker + "/" + op))
}
func queueSource(q *Queue, source *generation.Replica) bool {
	return source != nil && sameTrust(source.Trust(), q.authority.Generation)
}

// Enqueue acknowledges admission only after a durable intent and source pin.
// Re-delivery with the same operation is idempotent; changed signed bytes conflict.
func (q *Queue) Enqueue(ctx context.Context, source *generation.Replica, raw []byte) error {
	p, e := Verify(raw, q.authority)
	if e != nil {
		return e
	}
	if _, ok := p.worker(q.worker); !ok || !queueSource(q, source) || time.Now().Unix() >= p.ExpiresUnix {
		return ErrDenied
	}
	return q.edit(ctx, func(s *QueueState) error {
		if old, ok := s.Jobs[p.Operation]; ok {
			if !bytes.Equal(old.Plan, raw) {
				return ErrConflict
			}
			if old.Phase != "ADMITTING" {
				return nil
			}
		} else {
			if len(s.Jobs) >= q.limits.MaxJobs {
				return storage.ErrCapacity
			}
			s.Jobs[p.Operation] = QueueJob{Plan: append([]byte(nil), raw...), Phase: "ADMITTING", NextMillis: p.StartMillis}
			// Persist the intent before creating any pin or journal. A crash is replayable.
			if s.Revision == ^uint64(0) {
				return storage.ErrCapacity
			}
			s.Revision++
			if e := q.save(*s); e != nil {
				return e
			}
			if e := q.checkpoint("admission-intent"); e != nil {
				return e
			}
		}
		return q.admit(ctx, source, s, p.Operation)
	})
}
func (q *Queue) admit(ctx context.Context, source *generation.Replica, s *QueueState, op string) error {
	j := s.Jobs[op]
	p, e := Verify(j.Plan, q.authority)
	if e != nil {
		return e
	}
	if time.Now().Unix() >= p.ExpiresUnix {
		return ErrDenied
	}
	if e = source.Pin(ctx, q.pin(op), p.Generation, "generation"); e != nil {
		return e
	}
	if e = q.checkpoint("admission-pin"); e != nil {
		return e
	}
	journal, e := q.journal(j, true)
	if e != nil {
		return e
	}
	journal.Close()
	j.Phase = "QUEUED"
	s.Jobs[op] = j
	return nil
}
func (q *Queue) journal(job QueueJob, resumeAdmission bool) (*Journal, error) {
	p, e := Verify(job.Plan, q.authority)
	if e != nil {
		return nil, e
	}
	name := "jobs/" + p.Operation
	r, e := localfs.OpenAt(q.root, name, true)
	if e != nil {
		return nil, e
	}
	if _, e = regular(r, "state.json", maxJournal); errors.Is(e, os.ErrNotExist) && resumeAdmission && job.Phase == "ADMITTING" {
		saved, e := regular(r, "plan.json", MaxPlan)
		if errors.Is(e, os.ErrNotExist) {
			e = statefile.Guard(q.Admit, name+"/plan.json", len(job.Plan), func() error { return atomicFile(r, "plan.json", job.Plan) })
		} else if e == nil && !bytes.Equal(saved, job.Plan) {
			e = ErrConflict
		}
		if e != nil {
			r.Close()
			return nil, e
		}
		initial, _ := json.Marshal(State{Format: Format, Plan: storage.Hash(job.Plan), Worker: q.worker, Phase: "PENDING", Parts: map[string]Progress{}})
		if e = statefile.Guard(q.Admit, name+"/state.json", len(initial), func() error { return atomicFile(r, "state.json", initial) }); e != nil {
			r.Close()
			return nil, e
		}
	}
	j, e := openJournalRoot(r, job.Plan, q.worker, q.authority, false)
	if e == nil && q.Admit != nil {
		j.Admit = func(child string, size int) (func(bool) error, error) { return q.Admit(name+"/"+child, size) }
	}
	return j, e
}

// Retry is an explicit local operator action after correcting a blocked cause.
// It cannot revive expired authority, replace a plan, or release a source pin.
func (q *Queue) Retry(ctx context.Context, op string) error {
	return q.edit(ctx, func(s *QueueState) error {
		j, ok := s.Jobs[op]
		if !ok || j.Phase != "BLOCKED" {
			return ErrDenied
		}
		p, e := Verify(j.Plan, q.authority)
		if e != nil || time.Now().Unix() >= p.ExpiresUnix {
			return ErrDenied
		}
		j.Phase = "QUEUED"
		j.NextMillis = max(time.Now().UnixMilli(), p.StartMillis)
		j.ErrorCode = ""
		s.Jobs[op] = j
		return nil
	})
}
func (q *Queue) backoff(op string, attempt uint64) time.Duration {
	delay := int64(q.limits.RetryBaseMillis)
	for n := uint64(1); n < attempt && delay < int64(q.limits.RetryMaxMillis); n++ {
		delay = min(delay*2, int64(q.limits.RetryMaxMillis))
	}
	// Stable bounded jitter avoids synchronizing independent queues after restart.
	jitter := int64([]byte(op)[0]^[]byte(q.worker)[1]) % max(int64(1), delay/4)
	return time.Duration(min(delay+jitter, int64(q.limits.RetryMaxMillis))) * time.Millisecond
}
func queueError(e error) (string, bool) {
	switch {
	case errors.Is(e, storage.ErrUnavailable):
		return "UNAVAILABLE", true
	case errors.Is(e, context.DeadlineExceeded):
		return "DEADLINE", true
	case errors.Is(e, context.Canceled):
		return "CANCELLED", true
	case errors.Is(e, storage.ErrDenied), errors.Is(e, ErrDenied):
		return "AUTH", false
	case errors.Is(e, storage.ErrCapacity):
		return "CAPACITY", false
	case errors.Is(e, storage.ErrIntegrity):
		return "INTEGRITY", false
	case errors.Is(e, storage.ErrConflict), errors.Is(e, ErrConflict):
		return "CONFLICT", false
	case errors.Is(e, storage.ErrUnsupported):
		return "UNSUPPORTED", false
	default:
		return "LOCAL", false
	}
}

type BackendResolver func(context.Context, storage.Profile) (*storage.Backend, error)
type queueResult struct {
	op      string
	result  Result
	err     error
	retryAt time.Time
}

// Run drains admitted work. Transient failures retry without control-plane access;
// permanent failures/expiry remain visible and pinned. ErrBlocked is never success.
// Resolver must honor its context and supplies fresh credentials out of band.
func (q *Queue) Run(ctx context.Context, source *generation.Replica, resolve BackendResolver, key ed25519.PrivateKey) error {
	if !queueSource(q, source) || resolve == nil || len(key) != ed25519.PrivateKeySize || Identity(key.Public().(ed25519.PublicKey)) != q.worker {
		return ErrDenied
	}
	unlock, e := lock(ctx, q.root, "runner.lock")
	if e != nil {
		return e
	}
	defer unlock()
	if e = q.edit(ctx, func(s *QueueState) error {
		for op, j := range s.Jobs {
			if j.Phase == "RUNNING" {
				j.Phase = "RETRY_WAIT"
				s.Jobs[op] = j
			}
		}
		return nil
	}); e != nil {
		return e
	}
	work, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan queueResult, q.limits.Parallel)
	active := map[string]bool{}
	backends := map[string]*storage.Backend{}
	var backendMu sync.Mutex
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()
	// All state transitions happen on this goroutine. Cancellation joins attempts.
	finish := func(r queueResult) error {
		saveCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		err := q.edit(saveCtx, func(s *QueueState) error {
			j := s.Jobs[r.op]
			p, _ := Verify(j.Plan, q.authority)
			if r.err == nil {
				receipt := r.result.Receipt
				if receipt.Target != p.Profile.ID() || receipt.Generation != p.Generation || receipt.Operation != p.Operation || receipt.Executor != q.worker || receipt.Verification != "full-target-readback" || receipt.ObservedUnix < 1 {
					return ErrDenied
				}
				j.Phase = "COMPLETE"
				j.Receipt = &receipt
				j.ErrorCode = ""
				j.CleanupPending = true
			} else {
				code, retry := queueError(r.err)
				j.ErrorCode = code
				j.Phase = "BLOCKED"
				if retry {
					j.Phase = "RETRY_WAIT"
					j.NextMillis = min(p.ExpiresUnix*1000, max(time.Now().Add(q.backoff(r.op, j.Attempts)).UnixMilli(), r.retryAt.UnixMilli()))
				}
				if time.Now().Unix() >= p.ExpiresUnix {
					j.Phase = "EXPIRED"
					j.ErrorCode = "EXPIRED"
				}
			}
			s.Jobs[r.op] = j
			return nil
		})
		if err == nil && r.err == nil {
			return q.checkpoint("job-complete")
		}
		return err
	}
	defer func() {
		cancel()
		for len(active) > 0 {
			r := <-results
			delete(active, r.op)
			_ = finish(r)
		}
	}()
	for {
		if e = ctx.Err(); e != nil {
			return e
		}
		s, e := q.Status(ctx)
		if e != nil {
			return e
		}
		operations := make([]string, 0, len(s.Jobs))
		for op := range s.Jobs {
			operations = append(operations, op)
		}
		sort.Slice(operations, func(i, j int) bool {
			a, b := s.Jobs[operations[i]], s.Jobs[operations[j]]
			if a.NextMillis == b.NextMillis {
				return operations[i] < operations[j]
			}
			return a.NextMillis < b.NextMillis
		})
		pending, blocked := false, false
		for _, op := range operations {
			j := s.Jobs[op]
			p, _ := Verify(j.Plan, q.authority)
			if active[op] {
				pending = true
				continue
			}
			if j.Phase == "COMPLETE" {
				if j.CleanupPending {
					if e = q.release(ctx, source, op, j); e != nil {
						return e
					}
				}
				continue
			}
			if time.Now().Unix() >= p.ExpiresUnix && j.Phase != "EXPIRED" {
				if e = q.edit(ctx, func(s *QueueState) error {
					v := s.Jobs[op]
					v.Phase = "EXPIRED"
					v.ErrorCode = "EXPIRED"
					s.Jobs[op] = v
					return nil
				}); e != nil {
					return e
				}
				j.Phase = "EXPIRED"
			}
			if j.Phase == "BLOCKED" || j.Phase == "EXPIRED" {
				blocked = true
				continue
			}
			pending = true
			if len(active) >= q.limits.Parallel || time.Now().UnixMilli() < j.NextMillis {
				continue
			}
			if j.Phase == "ADMITTING" {
				e = q.edit(ctx, func(s *QueueState) error { return q.admit(ctx, source, s, op) })
				if e != nil {
					if saveErr := finish(queueResult{op: op, err: e}); saveErr != nil {
						return saveErr
					}
				}
				continue
			}
			if j.Attempts == ^uint64(0) {
				return storage.ErrCapacity
			}
			if e = q.edit(ctx, func(s *QueueState) error {
				v := s.Jobs[op]
				v.Phase = "RUNNING"
				v.Attempts++
				v.NextMillis = min(p.ExpiresUnix*1000, time.Now().Add(q.backoff(op, v.Attempts)).UnixMilli())
				s.Jobs[op] = v
				return nil
			}); e != nil {
				return e
			}
			attempt, stop := context.WithTimeout(work, time.Duration(q.limits.AttemptMillis)*time.Millisecond)
			active[op] = true
			go func(op string, job QueueJob, profile storage.Profile, attempt context.Context, stop context.CancelFunc) {
				defer stop()
				r := queueResult{op: op}
				backendMu.Lock()
				b := backends[profile.ID()]
				backendMu.Unlock()
				if b == nil {
					fresh, err := resolve(attempt, profile)
					if err == nil && (fresh == nil || fresh.Profile().ID() != profile.ID()) {
						err = ErrDenied
					}
					if err != nil {
						if fresh != nil {
							fresh.Close()
						}
						r.err = err
						results <- r
						return
					}
					backendMu.Lock()
					b = backends[profile.ID()]
					if b == nil {
						b = fresh
						backends[profile.ID()] = b
					} else {
						fresh.Close()
					}
					backendMu.Unlock()
				}
				journal, err := q.journal(job, false)
				if err == nil {
					r.result, err = journal.Run(attempt, source, b, key)
					journal.Close()
				}
				r.err = err
				r.retryAt = b.NextRequest()
				results <- r
			}(op, j, p.Profile, attempt, stop)
		}
		if !pending && len(active) == 0 {
			if blocked {
				return ErrBlocked
			}
			return nil
		}
		select {
		case r := <-results:
			delete(active, r.op)
			if e = finish(r); e != nil {
				return e
			}
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
func (q *Queue) release(ctx context.Context, source *generation.Replica, op string, j QueueJob) error {
	if e := source.ReleasePin(ctx, q.pin(op)); e != nil {
		return e
	}
	workerPin := storage.Hash([]byte(Format + "/pin/" + storage.Hash(j.Plan) + "/" + q.worker))
	if e := source.ReleasePin(ctx, workerPin); e != nil {
		return e
	}
	return q.edit(ctx, func(s *QueueState) error { v := s.Jobs[op]; v.CleanupPending = false; s.Jobs[op] = v; return nil })
}
