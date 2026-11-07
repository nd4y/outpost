package peer

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

const WindowReceiptFormat = "outpost-peer-window-1"
const windowProgressFormat = "outpost-peer-verification-progress-1"
const windowHeader = "Outpost-Batch-Verification"
const windowObjects = 8
const windowBytes = int64(generation.MaxObject)

type windowProgress struct {
	Format          string `json:"format"`
	Operation       string `json:"operationId"`
	Generation      string `json:"generation"`
	VerifiedObjects int    `json:"verifiedObjects"`
	TotalObjects    int    `json:"totalObjects"`
}

func verificationWindow(b Binding) string {
	raw, _ := json.Marshal(b)
	return generation.Hash(append([]byte(WindowReceiptFormat+"/"), raw...))
}
func (c *Client) completeRemote(ctx context.Context, b Binding, total int) (Receipt, error) {
	previous := 0
	for batch := 0; batch <= total; batch++ {
		r, e := c.request(ctx, b.Operation, b.Generation, "push", http.MethodPost, "complete", nil, 4096, nil)
		if e != nil {
			return Receipt{}, e
		}
		if r.status == http.StatusAccepted {
			var p windowProgress
			if decode(r.data, &p, 4096) != nil || p.Format != windowProgressFormat || p.Operation != b.Operation || p.Generation != b.Generation || p.TotalObjects != total || p.VerifiedObjects <= previous || p.VerifiedObjects >= total {
				return Receipt{}, ErrProtocol
			}
			previous = p.VerifiedObjects
			continue
		}
		var receipt Receipt
		if decode(r.data, &receipt, 4096) != nil || !validReceipt(receipt, b) || (receipt.Verification != "target-full-read" && receipt.Verification != "target-window-read") || receipt.ObservedUnix > time.Now().Add(5*time.Minute).Unix() {
			return Receipt{}, ErrProtocol
		}
		return receipt, nil
	}
	return Receipt{}, ErrProtocol
}
func (c *Client) completeLocal(ctx context.Context, b Binding, r *generation.Replica, total int) (Receipt, error) {
	for batch := 0; batch <= total; batch++ {
		if e := c.authorized(false); e != nil {
			return Receipt{}, e
		}
		result, e := r.VerifyWindow(ctx, b.Generation, verificationWindow(b), windowObjects, windowBytes)
		if e != nil {
			return Receipt{}, e
		}
		if result.Complete {
			return Receipt{WindowReceiptFormat, c.policy.Self, b.Generation, b.Expected, b.Operation, "local-window-read", result.VerifiedAt}, nil
		}
	}
	return Receipt{}, ErrUnavailable
}
