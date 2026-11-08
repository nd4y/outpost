package worker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"time"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
	"github.com/nd4y/outpost/internal/telemetry"
	"github.com/nd4y/outpost/internal/upload"
)

const externalHTTPFormat = "outpost-external-http-attempt-1"
const externalHTTPDirectory = "telemetry/http-attempts"
const maxExternalHTTPRecord = 4096

// A full page includes HTTP accounting and audit gauges with known markers.
const maxExternalHTTPMetricTargets = 6

type externalHTTPRecord struct {
	Format string `json:"format"`
	upload.HTTPAttempt
	Signature []byte `json:"signature,omitempty"`
}

func externalHTTPName(domain, target string) string {
	return storage.Hash([]byte(domain+"/"+target)) + ".json"
}

func readExternalHTTPAttempt(store *statefile.Store, node, domain, target string, public ed25519.PublicKey) (upload.HTTPAttempt, error) {
	var record externalHTTPRecord
	raw, err := store.Read(externalHTTPName(domain, target))
	if err != nil {
		return record.HTTPAttempt, err
	}
	if storage.Decode(raw, &record, maxExternalHTTPRecord) != nil || record.Format != externalHTTPFormat || record.Node != node || record.Domain != domain || record.Target != target || upload.Identity(public) != node || !record.HTTPAttempt.Valid(time.Now()) {
		return upload.HTTPAttempt{}, telemetry.ErrInvalid
	}
	signature := record.Signature
	record.Signature = nil
	unsigned, err := json.Marshal(record)
	if err != nil || !ed25519.Verify(public, append([]byte(externalHTTPFormat+"\x00"), unsigned...), signature) {
		return upload.HTTPAttempt{}, telemetry.ErrInvalid
	}
	return record.HTTPAttempt, nil
}

func (w *Worker) externalHTTPKey() ed25519.PrivateKey {
	key, ok := w.cert.PrivateKey.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize || upload.Identity(key.Public().(ed25519.PublicKey)) != w.node {
		return nil
	}
	return key
}

func (w *Worker) writeExternalHTTPAttempt(ctx context.Context, attempt upload.HTTPAttempt) error {
	if w.root == nil || w.budget == nil || attempt.Node != w.node || !attempt.Valid(time.Now()) {
		return telemetry.ErrInvalid
	}
	key := w.externalHTTPKey()
	if key == nil {
		return telemetry.ErrInvalid
	}
	if err := w.check(ctx); err != nil {
		return err
	}
	store, err := statefile.OpenAt(w.root, externalHTTPDirectory, maxExternalHTTPRecord, true)
	if err != nil {
		return err
	}
	defer store.Close()
	store.Admit = w.admission(externalHTTPDirectory)
	return store.WithLock(ctx, func() error {
		if err := w.check(ctx); err != nil {
			return err
		}
		prior, err := readExternalHTTPAttempt(store, w.node, attempt.Domain, attempt.Target, key.Public().(ed25519.PublicKey))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			same := prior.Operation == attempt.Operation && prior.Plan == attempt.Plan && prior.Attempt == attempt.Attempt
			if same {
				if prior.StartedMillis != attempt.StartedMillis {
					return telemetry.ErrConflict
				}
				if prior.Outcome != "STARTED" || attempt.Outcome == "STARTED" {
					// Lost local replies must not replace an observed result.
					x, _ := json.Marshal(prior)
					y, _ := json.Marshal(attempt)
					if bytes.Equal(x, y) {
						return nil
					}
					return telemetry.ErrConflict
				}
			} else {
				if attempt.Outcome != "STARTED" {
					return nil // an older parallel attempt finished after its successor
				}
				if prior.Operation == attempt.Operation && (prior.Plan != attempt.Plan || prior.Attempt >= attempt.Attempt) {
					return telemetry.ErrConflict
				}
				if prior.StartedMillis > attempt.StartedMillis || (prior.StartedMillis == attempt.StartedMillis && prior.Operation > attempt.Operation) {
					return nil
				}
			}
		} else if attempt.Outcome != "STARTED" {
			return telemetry.ErrConflict
		}
		record := externalHTTPRecord{Format: externalHTTPFormat, HTTPAttempt: attempt}
		unsigned, err := json.Marshal(record)
		if err != nil {
			return err
		}
		record.Signature = ed25519.Sign(key, append([]byte(externalHTTPFormat+"\x00"), unsigned...))
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return store.Write(externalHTTPName(attempt.Domain, attempt.Target), raw)
	})
}

// Each telemetry interval selects a bounded page of targets already present in
// the scoped snapshot. Missing, stale-scope and interrupted attempts stay unknown.
func (w *Worker) addExternalHTTPMetrics(ctx context.Context, domain string, interval int, snapshot management.Snapshot, record *telemetry.Record) {
	if snapshot.ExternalState != "OBSERVED" || interval < 1 || !storage.ID(domain) || snapshot.ObservedUnix < 1 {
		return
	}
	routes := map[string]map[string]bool{}
	audits := map[string]*management.ExternalAuditObservation{}
	for _, copy := range snapshot.ExternalCopies {
		if !storage.ID(copy.Target) || !storage.ID(copy.Operation) {
			continue
		}
		if routes[copy.Target] == nil {
			routes[copy.Target] = map[string]bool{}
		}
		routes[copy.Target][copy.Operation] = true
		if copy.Audit != nil {
			audits[copy.Target] = copy.Audit
		}
	}
	if len(routes) == 0 {
		return
	}
	targets := make([]string, 0, len(routes))
	for target := range routes {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	total := int64(len(targets))
	pages := (len(targets) + maxExternalHTTPMetricTargets - 1) / maxExternalHTTPMetricTargets
	page := int((snapshot.ObservedUnix / int64(interval)) % int64(pages))
	start := page * maxExternalHTTPMetricTargets
	selected := targets[start:min(start+maxExternalHTTPMetricTargets, len(targets))]
	selectedCount := int64(len(selected))
	record.Metrics = append(record.Metrics,
		telemetry.Metric{Name: "external_http_targets_in_scope", Value: &total},
		telemetry.Metric{Name: "external_http_targets_selected", Value: &selectedCount})
	var store *statefile.Store
	key := w.externalHTTPKey()
	if key != nil && w.root != nil && w.check(ctx) == nil {
		store, _ = statefile.OpenAt(w.root, externalHTTPDirectory, maxExternalHTTPRecord, false)
		if store != nil {
			defer store.Close()
		}
	}
	for _, target := range selected {
		var attempt upload.HTTPAttempt
		if store != nil && w.check(ctx) == nil {
			observed, err := readExternalHTTPAttempt(store, w.node, domain, target, key.Public().(ed25519.PublicKey))
			if err == nil && routes[target][observed.Operation] && observed.FinishedMillis/1000 <= snapshot.ObservedUnix {
				attempt = observed
			}
		}
		addExternalHTTPAttemptMetrics(record, target, attempt)
		addExternalAuditMetrics(record, target, audits[target])
	}
}

func addExternalAuditMetrics(record *telemetry.Record, target string, audit *management.ExternalAuditObservation) {
	var outcome, observed, expires *int64
	if audit != nil && audit.ObservedUnix > 0 && audit.ObservedUnix <= audit.FinishedUnix &&
		audit.FinishedUnix <= record.ObservedUnix && audit.ExpiresUnix > audit.ObservedUnix {
		observed, expires = &audit.ObservedUnix, &audit.ExpiresUnix
		if record.ObservedUnix < audit.ExpiresUnix {
			var code int64
			switch audit.State {
			case "VERIFIED_CIPHERTEXT":
				code = 1
			case "MISSING":
				code = 2
			case "INVALID_CONTENT":
				code = 3
			case "UNAVAILABLE":
				code = 4
			}
			if code != 0 {
				outcome = &code
			}
		}
	}
	record.Metrics = append(record.Metrics,
		telemetry.Metric{Name: "external_audit_result", Target: target, Value: outcome},
		telemetry.Metric{Name: "external_audit_observed_timestamp_seconds", Target: target, Value: observed},
		telemetry.Metric{Name: "external_audit_expires_timestamp_seconds", Target: target, Value: expires})
}

func addExternalHTTPAttemptMetrics(record *telemetry.Record, target string, attempt upload.HTTPAttempt) {
	var requests, sent, received, repeated, observed *int64
	if c := attempt.Counts; c != nil {
		at := attempt.FinishedMillis / 1000
		observed = &at
		if !c.Incomplete {
			requests, sent, received, repeated = &c.Requests, &c.RequestBytes, &c.ResponseBytes, &c.RepeatedRequestBytes
		}
	}
	record.Metrics = append(record.Metrics,
		telemetry.Metric{Name: "external_http_attempt_requests", Value: requests, Target: target},
		telemetry.Metric{Name: "external_http_attempt_request_body_bytes", Value: sent, Target: target},
		telemetry.Metric{Name: "external_http_attempt_response_body_bytes", Value: received, Target: target},
		telemetry.Metric{Name: "external_http_attempt_replayed_body_bytes", Value: repeated, Target: target},
		telemetry.Metric{Name: "external_http_attempt_observed_timestamp_seconds", Value: observed, Target: target})
}
