package worker

import (
	"path/filepath"

	"github.com/nd4y/outpost/internal/management"
	"github.com/nd4y/outpost/internal/policy"
	"github.com/nd4y/outpost/internal/storage"
)

const ReportProfileFormat = "outpost-report-profile-1"

// ReportProfile is provisioned locally. A remote command cannot change its
// endpoint, private file paths, TLS roots or reporting authority.
type ReportProfile struct {
	Format         string                    `json:"format"`
	Endpoint       string                    `json:"endpoint"`
	Identity       string                    `json:"identity"`
	Domain         string                    `json:"domain"`
	EnrollmentFile string                    `json:"enrollmentFile"`
	Schedule       management.DispatchConfig `json:"schedule"`
}

func LoadReportProfile(path string) (ReportProfile, error) {
	var p ReportProfile
	raw, e := ReadPrivate(path, 65536)
	if e != nil {
		return p, e
	}
	if DecodeInput(raw, &p, 65536) != nil || p.Format != ReportProfileFormat || !policy.Endpoint(p.Endpoint) || !storage.ID(p.Identity) || !storage.ID(p.Domain) || !filepath.IsAbs(p.EnrollmentFile) || p.Schedule.Validate() != nil {
		return p, ErrDenied
	}
	return p, nil
}
