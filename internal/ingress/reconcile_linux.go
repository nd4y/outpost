package ingress

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/storage"
)

type Reconciliation struct {
	Grant        string                          `json:"grant"`
	Intent       string                          `json:"intent"`
	Receiver     string                          `json:"receiver"`
	Phase        string                          `json:"phase"`
	ObservedUnix int64                           `json:"observedUnix"`
	Generation   string                          `json:"generation,omitempty"`
	Receipt      *Receipt                        `json:"receipt,omitempty"`
	Publication  *generation.PublicationEvidence `json:"publication,omitempty"`
}

// reconcile examines a stopped admission path while the registry lease and
// mutex exclude all writers for this slot. A fence without a session is still
// admission. A missing or unreadable registry is never a negative proof.
func (g *Registry) reconcile(ctx context.Context, intent Intent, grant Settlement) (Reconciliation, error) {
	out := Reconciliation{Grant: grant.ID, Intent: grant.Intent, Receiver: intent.Ingress, Phase: "UNKNOWN"}
	if bytes.Equal(g.state.Intent, g.options.SettlementIntent) {
		out.Phase = "FENCED"
		options := g.sessionOptions(g.state.Intent)
		options.Initialize = false
		s, err := openSessionFor(ctx, options, sessionInspect)
		if err == nil {
			defer s.Close()
			out.Phase = "ADMITTED"
			switch {
			case len(s.state.Retired) != 0:
				out.Phase = UnsealedRetired
			case s.state.Receipt != nil:
				out.Generation, out.Receipt, out.Phase = s.state.Receipt.Generation, s.state.Receipt, "RECEIPT"
			case len(s.state.Catalog) != 0:
				out.Generation, out.Phase = storage.Hash(s.state.Catalog), "SEALED"
				published, err := s.replica.PublishedEvidence(ctx, out.Generation)
				if err == nil {
					out.Publication, out.Phase = &published, "PUBLISHED_RECEIPT_MISSING"
				} else if !errors.Is(err, generation.ErrIncomplete) {
					return Reconciliation{}, err
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return Reconciliation{}, err
		}
	} else {
		status, err := g.options.Replica.Status(ctx)
		if err != nil {
			return Reconciliation{}, err
		}
		if status.HighestSequence == intent.Sequence-1 && status.LatestComplete == intent.Parent {
			if len(g.state.Intent) == 0 && intent.Sequence == 1 && g.state.ObservedUnix <= intent.NotBefore {
				if _, err = g.root.Lstat("current"); errors.Is(err, os.ErrNotExist) {
					out.Phase = "NOT_ADMITTED"
				}
			} else if len(g.state.Intent) != 0 {
				options := g.sessionOptions(g.state.Intent)
				options.Initialize = false
				s, err := openSessionFor(ctx, options, sessionInspect)
				if err == nil {
					defer s.Close()
					if s.state.Acknowledged && s.state.Receipt != nil && s.state.Receipt.Generation == intent.Parent &&
						s.intent.Sequence == intent.Sequence-1 && s.intent.Source == intent.Source &&
						s.intent.Profile == intent.Profile && s.intent.Domain == intent.Domain && s.intent.Repository == intent.Repository {
						out.Phase = "NOT_ADMITTED"
					}
				}
			}
		}
	}
	if grant.Purpose == SettlementRetireUnsealed && (out.Phase == "ADMITTED" || out.Phase == UnsealedRetired) {
		if err := g.checkPredecessor(ctx, intent); err != nil {
			return Reconciliation{}, err
		}
	}
	out.ObservedUnix = time.Now().Unix()
	if ctx.Err() != nil || !active(time.Unix(out.ObservedUnix, 0), grant.NotBefore, grant.ExpiresUnix) || out.ObservedUnix < g.state.ObservedUnix {
		return Reconciliation{}, ErrDenied
	}
	return out, nil
}

func (c *Client) Reconcile(ctx context.Context) (Reconciliation, error) {
	if !c.inspection {
		return Reconciliation{}, ErrDenied
	}
	return c.reconciliation(ctx, http.MethodGet, "reconcile")
}

func (c *Client) reconciliation(ctx context.Context, method, action string) (Reconciliation, error) {
	var out Reconciliation
	_, _, raw, err := c.request(ctx, method, action, nil, nil, MaxReceiptDocument+1024)
	if err != nil {
		return out, err
	}
	g, err := VerifySettlement(c.settlement, c.authority, c.intentRaw, c.owner, time.Now())
	if err != nil || decodeReply(raw, &out) != nil || out.Grant != g.ID || out.Intent != g.Intent ||
		out.Receiver != g.Ingress || out.ObservedUnix < g.NotBefore || out.ObservedUnix > time.Now().Unix() {
		return Reconciliation{}, ErrProtocol
	}
	valid := false
	switch out.Phase {
	case "UNKNOWN", "NOT_ADMITTED", "FENCED", "ADMITTED", UnsealedRetired:
		valid = out.Generation == "" && out.Receipt == nil && out.Publication == nil
	case "SEALED":
		valid = storage.ID(out.Generation) && out.Receipt == nil && out.Publication == nil
	case "PUBLISHED_RECEIPT_MISSING":
		p := out.Publication
		valid = p != nil && p.Generation == out.Generation && storage.ID(p.Generation) && storage.ID(p.Verification) &&
			p.VerifiedAt >= c.intent.NotBefore && p.VerifiedAt <= out.ObservedUnix && p.Objects >= 0 && p.Bytes >= 0 && out.Receipt == nil
	case "RECEIPT":
		r := out.Receipt
		valid = r != nil && r.Generation == out.Generation && out.Publication == nil && r.VerifiedAt <= out.ObservedUnix &&
			VerifyReceipt(*r, c.intent, c.authority, c.intentRaw, c.owner)
	}
	if !valid {
		return Reconciliation{}, ErrProtocol
	}
	return out, nil
}
