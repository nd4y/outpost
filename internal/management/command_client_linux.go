package management

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

// commandTransport shares the explicitly pinned reporting TLS connection.
// It accepts only paths constructed below from validated opaque identifiers.
func (c *ReportClient) commandTransport(ctx context.Context, method, path string, body []byte, out any, max int) error {
	req, e := http.NewRequestWithContext(ctx, method, c.endpoint+path, bytes.NewReader(body))
	if e != nil {
		return ErrInvalid
	}
	req.Header.Set("Accept-Encoding", "identity")
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Outpost-Request", "1")
	}
	res, e := c.client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrUnavailable
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 || peer.Identity(res.TLS.PeerCertificates[0]) != c.target || !time.Now().Before(res.TLS.PeerCertificates[0].NotAfter) {
		return ErrDenied
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusForbidden:
		return ErrDenied
	case http.StatusConflict:
		return ErrConflict
	case http.StatusTooManyRequests:
		return ErrCapacity
	default:
		return ErrUnavailable
	}
	media, _, e := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || res.Header.Get("Content-Encoding") != "" || res.ContentLength > int64(max) {
		return ErrInvalid
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, int64(max)+1))
	if e != nil || decodeHTTP(raw, out, max) != nil {
		return ErrInvalid
	}
	return nil
}
func (c *ReportClient) Commands(ctx context.Context, enrollment Enrollment, owner ed25519.PublicKey, limit int, cursor string) (CommandPage, error) {
	var out CommandPage
	if c == nil || enrollment.Node != c.node || !enrollment.Active(time.Now()) || len(owner) != 32 || limit < 1 || limit > 32 || len(cursor) > 512 {
		return out, ErrDenied
	}
	path := "/api/v1/tenants/" + enrollment.Tenant + "/nodes/" + c.node + "/commands?limit=" + strconv.Itoa(limit)
	if cursor != "" {
		path += "&cursor=" + url.QueryEscape(cursor)
	}
	if e := c.commandTransport(ctx, http.MethodGet, path, nil, &out, MaxCommandPage); e != nil {
		return CommandPage{}, e
	}
	if out.Format != "outpost-management-commands-2" || !safe(out.Revision) || len(out.Commands) > limit || out.Commands == nil || len(out.NextCursor) > 512 {
		return CommandPage{}, ErrInvalid
	}
	var previous uint64
	for _, queued := range out.Commands {
		envelope, a, e := command.VerifyEnvelope(queued.Document, owner)
		d, ok := enrollment.Domain(a.Domain)
		position := command.Position(queued.Sequence, envelope.Request.Kind)
		if e != nil || !ok || a.Node != c.node || a.Tenant != enrollment.Tenant || a.Repository != d.Repository || a.WriterEpoch > d.Epoch || envelope.Service != c.target || envelope.AdmittedUnix > time.Now().Unix() || envelope.Sequence != queued.Sequence || position <= previous || queued.Sequence > out.Revision {
			return CommandPage{}, ErrDenied
		}
		previous = position
	}
	return out, nil
}
func (c *ReportClient) AcknowledgeCommand(ctx context.Context, enrollment Enrollment, owner ed25519.PublicKey, envelope, raw []byte) (Receipt, error) {
	var out Receipt
	if c == nil || enrollment.Node != c.node || !enrollment.Active(time.Now()) {
		return out, ErrDenied
	}
	env, a, e := command.VerifyEnvelope(envelope, owner)
	if e != nil || env.Node != c.node || env.Service != c.target || a.Tenant != enrollment.Tenant {
		return out, ErrDenied
	}
	if _, ok := enrollment.Domain(a.Domain); !ok {
		return out, ErrDenied
	}
	ack, e := command.VerifyAck(raw, envelope, owner, enrollment.PublicKey, time.Now())
	if e != nil {
		return out, ErrDenied
	}
	body, _ := json.Marshal(struct {
		Document []byte `json:"document"`
	}{raw})
	path := "/api/v1/tenants/" + enrollment.Tenant + "/nodes/" + c.node + "/commands/" + env.Request.Operation + "/receipt"
	if e = c.commandTransport(ctx, http.MethodPut, path, body, &out, 4096); e != nil {
		return Receipt{}, e
	}
	expected := Receipt{Format: "outpost-management-receipt-1", Operation: ack.Operation, RequestDigest: commandRequestDigest(Principal{Actor: env.Actor}, env.Node, env.Request), State: ack.State, ObservedUnix: ack.ObservedUnix, ResultDigest: storage.Hash(raw), ErrorCode: ack.ErrorCode}
	if out != expected {
		return Receipt{}, ErrInvalid
	}
	return out, nil
}
