package management

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nd4y/outpost/internal/storage"
)

type reportRecord struct {
	Enrollment []byte `json:"enrollment"`
	Document   []byte `json:"document"`
}
type ReportView struct {
	Format                string       `json:"format"`
	Node                  string       `json:"node"`
	Tenant                string       `json:"tenant"`
	Domain                string       `json:"domain"`
	Sequence              uint64       `json:"sequence"`
	ConfigurationRevision uint64       `json:"configurationRevision"`
	ObservedUnix          int64        `json:"observedUnix"`
	InventoryState        string       `json:"inventoryState,omitempty"`
	State                 string       `json:"state"`
	DocumentDigest        string       `json:"documentDigest"`
	Generations           []Generation `json:"generations"`
	Jobs                  []Job        `json:"jobs"`
	Space                 Space        `json:"space"`
}

func reportKey(node, domain string) string {
	return storage.Hash([]byte("management-report\x00" + node + "\x00" + domain))
}
func reportFile(key string, slot int) string { return fmt.Sprintf("report-%s-%d.json", key, slot) }
func (r *Registry) readReport(s registryState, node, domain string) (Report, reportPointer, error) {
	var report Report
	k := reportKey(node, domain)
	p, ok := s.Reports[k]
	if !ok {
		return report, p, ErrUnavailable
	}
	raw, e := r.store.Read(reportFile(k, p.Slot))
	if e != nil {
		return report, p, e
	}
	var record reportRecord
	if canonical(raw, &record, maxRegistry) != nil || storage.Hash(record.Document) != p.Digest {
		return report, p, ErrInvalid
	}
	enrollment, e := VerifyEnrollment(record.Enrollment, r.owner)
	if e != nil {
		return report, p, e
	}
	report, e = VerifyReport(record.Document, enrollment, time.Now())
	if e != nil {
		return report, p, e
	}
	if report.Node != node || report.Domain != domain || report.Sequence != p.Sequence || report.ObservedUnix != p.ObservedUnix || report.EnrollmentRevision != p.EnrollmentRevision {
		return report, p, ErrInvalid
	}
	return report, p, nil
}
func reportReceipt(raw []byte, observed int64) Receipt {
	digest := storage.Hash(raw)
	return Receipt{Format: "outpost-management-receipt-1", Operation: storage.Hash([]byte("report-receipt\x00" + digest)), RequestDigest: digest, State: "COMPLETE", ObservedUnix: observed, ResultDigest: digest}
}

// PublishReport retains two bounded slots per node/domain. The signed registry
// switches the pointer only after the new slot is durable. A failed update can
// neither erase the previous observation nor manufacture a fresh timestamp.
func (r *Registry) PublishReport(ctx context.Context, actor, tenant, node string, raw []byte) (Receipt, error) {
	var out Receipt
	if !storage.ID(actor) || actor != node || !storage.ID(tenant) {
		return out, ErrDenied
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		enrollmentRaw, ok := s.Enrollments[node]
		if !ok {
			return ErrDenied
		}
		enrollment, e := VerifyEnrollment(enrollmentRaw, r.owner)
		if e != nil {
			return e
		}
		if enrollment.Tenant != tenant || !enrollment.Active(time.Now()) {
			return ErrDenied
		}
		next, e := VerifyReport(raw, enrollment, time.Now())
		if e != nil {
			return e
		}
		admission, _ := enrollment.Domain(next.Domain)
		fence := s.Domains[next.Domain]
		if admission.Epoch != fence.Epoch || admission.Repository != fence.Repository {
			return ErrDenied
		}
		key := reportKey(node, next.Domain)
		slot := 0
		if previous, exists := s.Reports[key]; exists {
			if _, _, e := r.readReport(s, node, next.Domain); e != nil {
				return e
			}
			if next.Sequence < previous.Sequence || next.ObservedUnix < previous.ObservedUnix {
				return ErrConflict
			}
			if next.Sequence == previous.Sequence {
				if storage.Hash(raw) != previous.Digest {
					return ErrConflict
				}
				out = reportReceipt(raw, previous.ObservedUnix)
				return nil
			}
			slot = 1 - previous.Slot
		} else if len(s.Reports) >= 16384 {
			return ErrCapacity
		}
		record, _ := json.Marshal(reportRecord{enrollmentRaw, raw})
		if e := r.store.Write(reportFile(key, slot), record); e != nil {
			return e
		}
		if e := r.point("management-report-slot-durable"); e != nil {
			return e
		}
		s.Reports[key] = reportPointer{Digest: storage.Hash(raw), Sequence: next.Sequence, ObservedUnix: next.ObservedUnix, EnrollmentRevision: next.EnrollmentRevision, Slot: slot}
		if e := r.save(s); e != nil {
			return e
		}
		if e := r.point("management-report-pointer-durable"); e != nil {
			return e
		}
		out = reportReceipt(raw, next.ObservedUnix)
		return nil
	})
	return out, e
}
func (r *Registry) Report(ctx context.Context, p Principal, tenant, node, domain string, maxAge time.Duration) (ReportView, error) {
	var out ReportView
	if p.Validate() != nil || !p.Allows(tenant, domain) || !storage.ID(node) || !storage.ID(domain) || !oneOfRole(p, "owner", "operator", "viewer", "recovery") || maxAge < time.Second || maxAge > 24*time.Hour {
		return out, ErrDenied
	}
	e := r.store.WithLock(ctx, func() error {
		if e := r.check(ctx); e != nil {
			return e
		}
		s, e := r.load()
		if e != nil {
			return e
		}
		enrollment, e := VerifyEnrollment(s.Enrollments[node], r.owner)
		if e != nil || enrollment.Tenant != tenant {
			return ErrUnavailable
		}
		if _, ok := enrollment.Domain(domain); !ok {
			return ErrUnavailable
		}
		report, pointer, e := r.readReport(s, node, domain)
		if e != nil {
			return e
		}
		if report.Tenant != tenant {
			return ErrInvalid
		}
		state := "CURRENT"
		if time.Now().Unix()-report.ObservedUnix > int64(maxAge/time.Second) || !enrollment.Active(time.Now()) || report.EnrollmentRevision != enrollment.Revision {
			state = "STALE"
		}
		out = ReportView{Format: "outpost-management-report-view-1", Node: node, Tenant: tenant, Domain: domain, Sequence: report.Sequence, ConfigurationRevision: report.ConfigurationRevision, ObservedUnix: report.ObservedUnix, InventoryState: report.InventoryState, State: state, DocumentDigest: pointer.Digest, Generations: report.Generations, Jobs: report.Jobs, Space: report.Space}
		return nil
	})
	return out, e
}
func oneOfRole(p Principal, roles ...string) bool {
	for _, role := range roles {
		if p.Role(role) {
			return true
		}
	}
	return false
}
