package worker

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"time"

	"github.com/nd4y/outpost/internal/diskbudget"
	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/telemetry"
)

const TelemetryProfileFormat = "outpost-telemetry-profile-1"

type TelemetryProfile struct {
	Format          string `json:"format"`
	Endpoint        string `json:"endpoint"`
	Identity        string `json:"identity"`
	Domain          string `json:"domain"`
	EnrollmentFile  string `json:"enrollmentFile"`
	MaxBytes        int    `json:"maxBytes"`
	MaxItems        int    `json:"maxItems"`
	IntervalSeconds int    `json:"intervalSeconds"`
	Enabled         bool   `json:"enabled"`
}

func (p TelemetryProfile) Validate() error {
	if p.Format != TelemetryProfileFormat || !policy.Endpoint(p.Endpoint) || !storage.ID(p.Identity) || !storage.ID(p.Domain) || !filepath.IsAbs(p.EnrollmentFile) || p.MaxBytes < 4096 || p.MaxBytes > 4<<20 || p.MaxItems < 1 || p.MaxItems > 128 || p.IntervalSeconds < 1 || p.IntervalSeconds > 86400 {
		return ErrDenied
	}
	return nil
}
func LoadTelemetryProfile(path string) (TelemetryProfile, error) {
	var p TelemetryProfile
	raw, e := ReadPrivate(path, 65536)
	if e != nil {
		return p, e
	}
	if DecodeInput(raw, &p, 65536) != nil || p.Validate() != nil {
		return p, ErrDenied
	}
	return p, nil
}

type Telemetry struct {
	*telemetry.Outbox
	ownedBudget *diskbudget.Budget
	profile     TelemetryProfile
}

func (t *Telemetry) Close() error {
	e := t.Outbox.Close()
	if t.ownedBudget != nil {
		e = errors.Join(e, t.ownedBudget.Close())
	}
	return e
}
func (w *Worker) OpenTelemetry(ctx context.Context, p TelemetryProfile, enrollment []byte, initialize bool) (*Telemetry, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	cached, e := w.cache.Raw(ctx)
	if e != nil {
		return nil, e
	}
	cfg, e := w.cache.Verify(cached)
	if e != nil {
		return nil, e
	}
	budget, owned, e := w.reportingBudget(ctx, cfg)
	if e != nil {
		return nil, e
	}
	relative := "telemetry/otlp/" + storage.Hash([]byte(p.Identity+"/"+p.Domain))
	// Endpoint/identity/domain/limits/owner are immutable. Schedule and the local
	// grant file path are not export authority and can change without a reset.
	binding, _ := json.Marshal(struct {
		Endpoint, Identity, Domain string
		Bytes, Items               int
		Owner                      ed25519.PublicKey
	}{p.Endpoint, p.Identity, p.Domain, p.MaxBytes, p.MaxItems, w.owner})
	q, e := telemetry.Open(telemetry.Options{Root: w.root, Directory: relative, Signer: w.cert.PrivateKey.(ed25519.PrivateKey), Target: p.Identity, Domain: p.Domain, Binding: storage.Hash(binding), MaxBytes: p.MaxBytes, MaxItems: p.MaxItems, Initialize: initialize, Guard: w.check, Admission: budget.Admission(relative), Owner: w.owner, Enrollment: enrollment, Authorize: func(ctx context.Context, g management.Enrollment) error {
		_, e := w.reportConfiguration(ctx, g, p.Domain)
		return e
	}})
	if e != nil {
		if owned {
			budget.Close()
		}
		return nil, e
	}
	out := &Telemetry{Outbox: q, profile: p}
	if owned {
		out.ownedBudget = budget
	}
	return out, nil
}

// TelemetryRecord projects already scoped metadata. It exposes no arbitrary
// text, job payloads or source names. Verification remains the original age of
// the latest complete local generation, never the time of this observation.
func TelemetryRecord(s management.Snapshot, node string) (telemetry.Record, error) {
	r := telemetry.Record{ObservedUnix: s.ObservedUnix}
	number := func(v int64) *int64 { return &v }
	add := func(name string, value *int64) {
		r.Metrics = append(r.Metrics, telemetry.Metric{Name: name, Value: value})
	}
	if s.ConfigurationRevision > math.MaxInt64 {
		return r, telemetry.ErrInvalid
	}
	add("report_observed_timestamp_seconds", number(s.ObservedUnix))
	add("configuration_revision", number(int64(s.ConfigurationRevision)))
	counts := map[string]int64{"jobs_queued": 0, "jobs_running": 0, "jobs_retry_wait": 0, "jobs_blocked": 0}
	for _, j := range s.Jobs {
		switch j.Phase {
		case "QUEUED":
			counts["jobs_queued"]++
		case "RUNNING":
			counts["jobs_running"]++
		case "RETRY_WAIT":
			counts["jobs_retry_wait"]++
		case "BLOCKED", "FAILED":
			counts["jobs_blocked"]++
		case "COMPLETE", "PAUSED", "WITHDRAWN":
		default:
			return r, telemetry.ErrInvalid
		}
	}
	for _, name := range []string{"jobs_queued", "jobs_running", "jobs_retry_wait", "jobs_blocked"} {
		add(name, number(counts[name]))
	}
	for _, m := range []telemetry.Metric{{Name: "space_physical_bytes", Value: s.Space.PhysicalBytes}, {Name: "space_free_bytes", Value: s.Space.FreeBytes}, {Name: "space_accounted_bytes", Value: s.Space.AccountedBytes}, {Name: "space_reserved_bytes", Value: s.Space.ReservedBytes}} {
		if s.Space.State != "OBSERVED" {
			m.Value = nil
		}
		r.Metrics = append(r.Metrics, m)
	}
	var latest management.Generation
	complete := int64(0)
	event := telemetry.Event{Kind: "STATE_CHANGED", State: "UNAVAILABLE", Target: node}
	if s.InventoryState == "OBSERVED" {
		add("inventory_available", number(1))
		for _, g := range s.Generations {
			if g.Status == "COMPLETE" {
				complete++
				if g.Sequence > latest.Sequence {
					latest = g
				}
			}
		}
		if latest.Sequence > math.MaxInt64 {
			return r, telemetry.ErrInvalid
		}
		add("complete_generations", number(complete))
		add("latest_generation_sequence", number(int64(latest.Sequence)))
		event.State = "OBSERVED"
		if latest.Generation != "" {
			event.State = "COMPLETE"
			event.Operation = latest.Generation
		}
	} else {
		add("inventory_available", number(0))
		add("complete_generations", nil)
		add("latest_generation_sequence", nil)
	}
	var verified *int64
	if latest.Verification == "CIPHERTEXT" && latest.VerifiedUnix > 0 {
		verified = number(latest.VerifiedUnix)
	}
	r.Metrics = append(r.Metrics, telemetry.Metric{Name: "copy_verified_timestamp_seconds", Value: verified, Target: node})
	r.Events = []telemetry.Event{event}
	return r, r.Validate()
}

type TelemetryStep struct {
	Queue  telemetry.Status `json:"queue"`
	Sample string           `json:"sample"`
}

func (w *Worker) TelemetryOnce(ctx context.Context, p TelemetryProfile, q *Telemetry, sender telemetry.Sender) (TelemetryStep, error) {
	out := TelemetryStep{Sample: "PAUSED"}
	if q == nil || p.Validate() != nil || p.Identity != q.profile.Identity || p.Domain != q.profile.Domain || p.Endpoint != q.profile.Endpoint || p.MaxBytes != q.profile.MaxBytes || p.MaxItems != q.profile.MaxItems {
		return out, telemetry.ErrConflict
	}
	if !p.Enabled {
		s, e := q.Status(ctx)
		out.Queue = s
		return out, e
	}
	raw, e := q.Enrollment(ctx)
	if e != nil {
		return out, e
	}
	snapshot, e := w.ManagementSnapshot(ctx, raw, p.Domain)
	if e != nil {
		return out, e
	}
	record, e := TelemetryRecord(snapshot, w.node)
	if e != nil {
		return out, e
	}
	w.addExternalHTTPMetrics(ctx, p.Domain, p.IntervalSeconds, snapshot, &record)
	sampled, e := q.Observe(ctx, record, time.Duration(p.IntervalSeconds)*time.Second)
	out.Sample = "UNCHANGED"
	if sampled {
		out.Sample = "SAMPLED"
	}
	if errors.Is(e, telemetry.ErrCapacity) || errors.Is(e, statefile.ErrCapacity) {
		out.Sample = "CAPACITY_BLOCKED"
	} else if e != nil {
		return out, e
	}
	out.Queue, e = q.Deliver(ctx, sender)
	return out, e
}
func (w *Worker) RunTelemetry(ctx context.Context, p TelemetryProfile, q *Telemetry, sender telemetry.Sender) error {
	if p.Validate() != nil || !p.Enabled {
		return ErrDenied
	}
	for {
		if _, e := w.TelemetryOnce(ctx, p, q, sender); e != nil {
			return e
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
