// Package telemetry provides a bounded, typed OTLP outbox. It never reads
// backup payloads or forwards arbitrary application logs.
package telemetry

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"

	"github.com/nd4y/outpost/internal/storage"
)

const Format = "outpost-telemetry-1"
const MaxFrame = 64 << 10
const MaxRecords = 128

var (
	ErrInvalid  = errors.New("invalid telemetry record")
	ErrConflict = errors.New("telemetry binding conflict")
	ErrCapacity = errors.New("telemetry capacity reached")
	ErrBlocked  = errors.New("telemetry delivery blocked")
)

// Metric names and labels are closed vocabularies. A nil value is explicitly
// unknown and must not be rendered as a measured zero.
type Metric struct {
	Name   string `json:"name"`
	Value  *int64 `json:"value"`
	Target string `json:"target,omitempty"`
}
type Event struct {
	Kind      string `json:"kind"`
	State     string `json:"state"`
	Operation string `json:"operation,omitempty"`
	Target    string `json:"target,omitempty"`
	Code      string `json:"code,omitempty"`
}
type Record struct {
	ObservedUnix int64    `json:"observedUnix"`
	Metrics      []Metric `json:"metrics,omitempty"`
	Events       []Event  `json:"events,omitempty"`
}
type Message struct {
	Signal string `json:"signal"`
	Body   []byte `json:"body"`
	Digest string `json:"digest"`
}

var metricNames = map[string]bool{
	"report_observed_timestamp_seconds": true, "configuration_revision": true,
	"jobs_queued": true, "jobs_running": true, "jobs_retry_wait": true, "jobs_blocked": true,
	"space_physical_bytes": true, "space_free_bytes": true, "space_accounted_bytes": true, "space_reserved_bytes": true,
	"inventory_available": true, "complete_generations": true, "latest_generation_sequence": true,
	"copy_verified_timestamp_seconds": true,
	"external_http_targets_in_scope":  true, "external_http_targets_selected": true,
	"external_http_attempt_requests": true, "external_http_attempt_request_body_bytes": true,
	"external_http_attempt_response_body_bytes": true, "external_http_attempt_replayed_body_bytes": true,
	"external_http_attempt_observed_timestamp_seconds": true,
}

func member(value string, choices ...string) bool {
	for _, v := range choices {
		if value == v {
			return true
		}
	}
	return false
}
func optionalID(value string) bool { return value == "" || storage.ID(value) }
func (r Record) Validate() error {
	if r.ObservedUnix < 1 || r.ObservedUnix > math.MaxInt64/1000000000 || len(r.Metrics)+len(r.Events) < 1 || len(r.Metrics) > MaxRecords || len(r.Events) > MaxRecords {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, m := range r.Metrics {
		key := m.Name + "/" + m.Target
		if !metricNames[m.Name] || !optionalID(m.Target) || seen[key] || m.Value != nil && *m.Value < 0 {
			return ErrInvalid
		}
		seen[key] = true
	}
	for _, e := range r.Events {
		if !member(e.Kind, "STATE_CHANGED", "DELIVERY_BLOCKED", "RECOVERED", "SOURCE_STALE", "CAPACITY_BLOCKED") || !member(e.State, "UNKNOWN", "READY", "QUEUED", "RUNNING", "RETRY_WAIT", "BLOCKED", "COMPLETE", "UNAVAILABLE", "PAUSED", "WITHDRAWN", "OBSERVED") || !optionalID(e.Operation) || !optionalID(e.Target) || !member(e.Code, "", "UNAVAILABLE", "DENIED", "INVALID", "CONFLICT", "CAPACITY", "DEADLINE", "CANCELED", "PARTIAL_REJECTION", "PERMANENT_REJECTION") {
			return ErrInvalid
		}
	}
	raw, e := json.Marshal(r)
	if e != nil || len(raw) > MaxFrame {
		return ErrCapacity
	}
	return nil
}

type attribute struct {
	Key   string            `json:"key"`
	Value map[string]string `json:"value"`
}

func attr(key, value string) attribute {
	return attribute{key, map[string]string{"stringValue": value}}
}
func attributes(node, domain, target string) []attribute {
	out := []attribute{attr("outpost.node", node), attr("outpost.domain", domain)}
	if target != "" {
		out = append(out, attr("outpost.target", target))
	}
	return out
}

// Encode fixes signal payloads before admission. A retry sends these bytes,
// including the original observation timestamp, without regenerating them.
func Encode(node, domain string, r Record) ([]Message, error) {
	if !storage.ID(node) || !storage.ID(domain) {
		return nil, ErrInvalid
	}
	if e := r.Validate(); e != nil {
		return nil, e
	}
	timestamp := strconv.FormatInt(r.ObservedUnix*1000000000, 10)
	resource := map[string]any{"attributes": []attribute{attr("service.name", "outpost")}}
	scope := map[string]string{"name": "outpost.telemetry", "version": Format}
	out := []Message{}
	appendSignal := func(signal string, value any) error {
		raw, e := json.Marshal(value)
		if e != nil || len(raw) > MaxFrame {
			return ErrCapacity
		}
		out = append(out, Message{signal, raw, storage.Hash(raw)})
		return nil
	}
	if len(r.Metrics) > 0 {
		metrics := []any{}
		for _, m := range r.Metrics {
			labels := attributes(node, domain, m.Target)
			gauge := func(name string, value int64) any {
				return map[string]any{"name": "outpost_" + name, "gauge": map[string]any{"dataPoints": []any{map[string]any{"attributes": labels, "timeUnixNano": timestamp, "asInt": strconv.FormatInt(value, 10)}}}}
			}
			known := int64(0)
			if m.Value != nil {
				known = 1
				metrics = append(metrics, gauge(m.Name, *m.Value))
			}
			metrics = append(metrics, gauge(m.Name+"_known", known))
		}
		if e := appendSignal("metrics", map[string]any{"resourceMetrics": []any{map[string]any{"resource": resource, "scopeMetrics": []any{map[string]any{"scope": scope, "metrics": metrics}}}}}); e != nil {
			return nil, e
		}
	}
	if len(r.Events) > 0 {
		logs := []any{}
		for _, e := range r.Events {
			labels := append(attributes(node, domain, e.Target), attr("outpost.state", e.State))
			if e.Operation != "" {
				labels = append(labels, attr("outpost.operation", e.Operation))
			}
			if e.Code != "" {
				labels = append(labels, attr("outpost.error_code", e.Code))
			}
			logs = append(logs, map[string]any{"timeUnixNano": timestamp, "severityNumber": 9, "body": map[string]string{"stringValue": e.Kind}, "attributes": labels})
		}
		if e := appendSignal("logs", map[string]any{"resourceLogs": []any{map[string]any{"resource": resource, "scopeLogs": []any{map[string]any{"scope": scope, "logRecords": logs}}}}}); e != nil {
			return nil, e
		}
	}
	return out, nil
}
