package capture

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/ingress"
)

// IngressReadback reports the selected receiver's historical attestation of
// ciphertext readback for one capture.
type IngressReadback struct {
	Target       string `json:"target"`
	Generation   string `json:"generation"`
	Verification string `json:"verification"`
	Provenance   string `json:"provenance"`
	VerifiedUnix int64  `json:"verifiedUnix"`
}

// CommittedIngressReadback inspects the private capture journal. The active
// source selects the job using its held execution lease and current route.
func (j *Job) CommittedIngressReadback(ctx context.Context) (*IngressReadback, error) {
	var out *IngressReadback
	err := j.state.WithLock(ctx, func() error {
		if err := j.guard(ctx); err != nil {
			return err
		}
		now := time.Now()
		authority, err := ingress.VerifyAuthority(j.options.Authority, j.options.Owner, now)
		if err != nil {
			return nil
		}
		raw, err := j.state.Read("job.json")
		if err != nil {
			return err
		}
		s, err := j.decodeState(raw)
		if err != nil || s.Receipt == nil || phase(s.Phase) < phase("WAITING_COPIES") {
			return err
		}
		receipt := *s.Receipt
		if receipt.VerifiedAt < j.intent.SnapshotUnix || receipt.VerifiedAt > s.ObservedUnix ||
			receipt.VerifiedAt > now.Unix() || s.CompletedFiles != len(j.plan.Files) ||
			!ingress.VerifyReceipt(receipt, j.intent, j.options.Authority, j.options.Intent, j.options.Owner) {
			return ErrInvalid
		}
		catalog, err := j.state.Read("catalog.json")
		if err != nil {
			return err
		}
		if _, err = j.sealedHeads(catalog, s.Generation); err != nil {
			return err
		}
		// The checkpoint may be durable before the job reaches CHECKPOINTED. In
		// either phase, use its writer signature when comparing the receipt.
		checkpoint, err := j.state.Read("checkpoint.json")
		if err == nil {
			c, err := VerifyCheckpoint(checkpoint, j.authority.Trust)
			if err != nil || c.Profile != j.intent.Profile || c.View != j.options.Profile.View ||
				c.Sequence != j.intent.Sequence || c.Receipt != receipt {
				return ErrInvalid
			}
		} else if !errors.Is(err, os.ErrNotExist) || phase(s.Phase) >= phase("CHECKPOINTED") {
			return err
		}
		if err = j.guard(ctx); err != nil {
			return err
		}
		finished := time.Now().Unix()
		if finished >= authority.ExpiresUnix || finished < now.Unix() {
			return nil
		}
		out = &IngressReadback{Target: receipt.Ingress, Generation: receipt.Generation,
			Verification: "CIPHERTEXT_READBACK", Provenance: "RECEIVER_ATTESTED", VerifiedUnix: receipt.VerifiedAt}
		return nil
	})
	return out, err
}
