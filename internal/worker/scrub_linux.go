package worker

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
	"sort"
	"strconv"
	"time"
)

// Scheduled scrubs use the same worker slots and cancellation lifetime as
// transfers. The successful observation time is historical, not poll time.
type ScrubState struct {
	Domain          string `json:"domain"`
	Repository      string `json:"repository"`
	Epoch           uint64 `json:"epoch"`
	Generation      string `json:"generation"`
	Window          string `json:"window"`
	Phase           string `json:"phase"`
	StartedUnix     int64  `json:"startedUnix"`
	VerifiedUnix    int64  `json:"verifiedUnix"`
	FinishedUnix    int64  `json:"finishedUnix"`
	NextMillis      int64  `json:"nextMillis"`
	Attempts        uint64 `json:"attempts"`
	VerifiedObjects int    `json:"verifiedObjects"`
	TotalObjects    int    `json:"totalObjects"`
	ErrorCode       string `json:"errorCode,omitempty"`
	HealthToken     string `json:"healthToken,omitempty"`
}

func scrubKey(domain, repository string, epoch uint64, id string) string {
	return storage.Hash([]byte(domain + "/" + repository + "/" + strconv.FormatUint(epoch, 10) + "/" + id))
}
func validateScrubs(s Status) error {
	if s.Format != ScheduledFormat && s.Format != RecoveryFormat {
		if s.Scrubs != nil {
			return ErrDenied
		}
		return nil
	}
	if s.Format == ScheduledFormat && len(s.Scrubs) == 0 || len(s.Scrubs) > MaxJobs {
		return ErrDenied
	}
	for key, entry := range s.Scrubs {
		if !storage.ID(entry.Domain) || !storage.ID(entry.Repository) || !storage.ID(entry.Generation) || !storage.ID(entry.Window) || entry.Epoch == 0 || key != scrubKey(entry.Domain, entry.Repository, entry.Epoch, entry.Generation) || entry.StartedUnix < 1 || entry.VerifiedUnix < 0 || entry.FinishedUnix < 0 || entry.NextMillis < 0 || entry.Attempts == 0 || entry.VerifiedObjects < 0 || entry.TotalObjects < entry.VerifiedObjects || entry.TotalObjects > generation.MaxObjects {
			return ErrDenied
		}
		switch entry.Phase {
		case "RUNNING", "QUEUED", "RETRY_WAIT", "CORRUPT", "COMPLETE":
		default:
			return ErrDenied
		}
		if entry.Phase == "COMPLETE" && (entry.VerifiedUnix == 0 || entry.FinishedUnix < entry.StartedUnix || entry.VerifiedObjects != entry.TotalObjects || entry.TotalObjects == 0) {
			return ErrDenied
		}
		if entry.HealthToken != "" && !storage.ID(entry.HealthToken) {
			return ErrDenied
		}
		if entry.ErrorCode != "" {
			switch entry.ErrorCode {
			case "CANCELED", "DEADLINE", "CAPACITY_BLOCKED", "POLICY_EXPIRED", "POLICY_BLOCKED", "CONFLICT", "DATA_INCOMPLETE", "TARGET_BLOCKED", "RETRY_REQUIRED":
			default:
				return ErrDenied
			}
		}
	}
	return nil
}

type scrubResult struct {
	key, window string
	checked     generation.BatchResult
	err         error
}
type scrubCandidate struct {
	key         string
	domain      control.Domain
	generation  string
	due         int64
	fresh       bool
	healthToken string
}

func (w *Worker) scheduleScrub(v *view, running map[string]bool, results chan<- result) error {
	now := time.Now()
	if v.ctx.Err() != nil {
		return nil
	}
	if now.Before(v.nextScrubScan) {
		return nil
	}
	v.nextScrubScan = now.Add(time.Second)
	enabled := false
	for _, d := range v.cfg.Domains {
		if d.ScrubIntervalSeconds > 0 && !v.paused(d.Trust.Domain, "") {
			enabled = true
			break
		}
	}
	if !enabled {
		return nil
	}
	status, e := w.Status(v.ctx)
	if e != nil {
		return e
	}
	if status.Controls == nil {
		return ErrDenied
	}
	candidates := []scrubCandidate{}
	for _, d := range v.cfg.Domains {
		if d.ScrubIntervalSeconds == 0 || v.paused(d.Trust.Domain, "") || status.Controls.paused(d.Trust.Domain, "") {
			continue
		}
		local := v.domains[d.Trust.Domain]
		if local == nil {
			continue
		}
		entries, e := local.replica.Recorded(v.ctx)
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !entry.Complete {
				continue
			}
			key := scrubKey(d.Trust.Domain, d.Trust.Repository, d.Trust.Epoch, entry.Generation)
			if running["scrub/"+key] {
				continue
			}
			old, exists := status.Scrubs[key]
			due := old.NextMillis
			fresh := !exists || old.Phase == "COMPLETE" || old.Phase == "CORRUPT" || old.HealthToken != entry.RepairToken
			if old.Phase == "COMPLETE" {
				due = (old.FinishedUnix + d.ScrubIntervalSeconds) * 1000
			}
			if old.Phase == "CORRUPT" {
				due = 0
			} // publication was repaired since detection
			if old.HealthToken != entry.RepairToken {
				due = 0
			}
			if now.Unix() < old.StartedUnix || now.Unix() < old.FinishedUnix || now.Unix() < old.VerifiedUnix {
				return ErrDenied
			}
			if due <= now.UnixMilli() {
				candidates = append(candidates, scrubCandidate{key, d, entry.Generation, due, fresh, entry.RepairToken})
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].due == candidates[j].due {
			return candidates[i].key < candidates[j].key
		}
		return candidates[i].due < candidates[j].due
	})
	chosen := candidates[0]
	var window string
	e = w.update(v.ctx, func(s *Status) error {
		if controlRevision(s.Controls) != controlRevision(v.controls) {
			v.cancel()
			return context.Canceled
		}
		if s.Format == LegacyFormat {
			return ErrDenied
		}
		old, exists := s.Scrubs[chosen.key]
		if !exists && len(s.Scrubs) >= MaxJobs {
			return ErrCapacity
		}
		if chosen.fresh {
			var nonce [32]byte
			if _, e := rand.Read(nonce[:]); e != nil {
				return e
			}
			old = ScrubState{Domain: chosen.domain.Trust.Domain, Repository: chosen.domain.Trust.Repository, Epoch: chosen.domain.Trust.Epoch, Generation: chosen.generation, Window: storage.Hash(nonce[:]), StartedUnix: now.Unix(), VerifiedUnix: old.VerifiedUnix, HealthToken: chosen.healthToken}
		}
		if old.Attempts == ^uint64(0) {
			return ErrCapacity
		}
		old.Attempts++
		old.Phase = "RUNNING"
		old.ErrorCode = ""
		old.NextMillis = 0
		if s.Scrubs == nil {
			s.Scrubs = map[string]ScrubState{}
		}
		if s.Format != RecoveryFormat {
			s.Format = ScheduledFormat
		}
		s.Scrubs[chosen.key] = old
		window = old.Window
		return nil
	})
	if e != nil {
		return e
	}
	if e = w.point("worker-scrub-intent-durable"); e != nil {
		return e
	}
	running["scrub/"+chosen.key] = true
	go func() {
		deadline := time.Now().Add(time.Duration(v.cfg.Limits.AttemptMillis) * time.Millisecond)
		expiry := time.Unix(v.cfg.ExpiresUnix, 0)
		if expiry.Before(deadline) {
			deadline = expiry
		}
		ctx, cancel := context.WithDeadline(v.ctx, deadline)
		defer cancel()
		checked, e := v.domains[chosen.domain.Trust.Domain].replica.VerifyWindow(ctx, chosen.generation, window, 8, generation.MaxObject)
		if e == nil {
			e = w.point("worker-scrub-batch-durable")
		}
		if e == nil {
			e = ctx.Err()
		}
		if e == nil {
			e = v.cfg.Active(time.Now())
		}
		results <- result{scrub: &scrubResult{chosen.key, window, checked, e}}
	}()
	return nil
}
func (w *Worker) finishScrub(ctx context.Context, v *view, out *scrubResult) error {
	e := w.update(ctx, func(s *Status) error {
		item, ok := s.Scrubs[out.key]
		if !ok || item.Window != out.window {
			return ErrDenied
		}
		now := time.Now()
		if now.Unix() < item.StartedUnix {
			return ErrDenied
		}
		item.ErrorCode = errorCode(out.err)
		if out.checked.Generation == item.Generation {
			item.VerifiedObjects = out.checked.VerifiedObjects
			item.TotalObjects = out.checked.TotalObjects
		}
		switch {
		case out.err == nil && out.checked.Complete:
			item.Phase = "COMPLETE"
			item.VerifiedUnix = out.checked.VerifiedAt
			item.FinishedUnix = now.Unix()
			item.NextMillis = 0
		case out.err == nil:
			item.Phase = "QUEUED"
			item.NextMillis = now.Add(250 * time.Millisecond).UnixMilli()
		case v.ctx.Err() != nil && (errors.Is(out.err, context.Canceled) || errors.Is(out.err, context.DeadlineExceeded)):
			item.Phase = "QUEUED"
			item.NextMillis = 0
		case errors.Is(out.err, generation.ErrIncomplete):
			item.Phase = "CORRUPT"
			item.NextMillis = 0
		default:
			item.Phase = "RETRY_WAIT"
			item.NextMillis = now.Add(time.Duration(1<<min(item.Attempts, 6)) * time.Second).UnixMilli()
		}
		s.Scrubs[out.key] = item
		return nil
	})
	if e != nil {
		return e
	}
	return w.point("worker-scrub-result-durable")
}
