package peer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

type Client struct {
	http        *http.Client
	endpoint    *url.URL
	peer        string
	policy      Policy
	journal     *Journal
	trust       generation.Trust
	limits      Limits
	certificate *x509.Certificate
	repair      string
}
type Result struct {
	CachedObjects  int      `json:"cachedObjects,omitempty"`
	Receipt        Receipt  `json:"receipt"`
	TargetReceipt  *Receipt `json:"targetReceipt,omitempty"`
	Counters       Counters `json:"counters"`
	CleanupPending bool     `json:"cleanupPending"`
}

func NewClient(endpoint, target string, cert tls.Certificate, roots *x509.CertPool, policy Policy, journal *Journal, trust generation.Trust, limits Limits) (*Client, error) {
	if journal == nil || policy.validate(trust) != nil || journal.identity.Self != policy.Self || journal.identity.Domain != policy.Domain || journal.identity.Repository != policy.Repository || journal.identity.Epoch != policy.Epoch {
		return nil, ErrDenied
	}
	if _, ok := policy.Peers[target]; !ok {
		return nil, ErrDenied
	}
	client, u, e := clientHTTP(endpoint, cert, roots, policy.Self, target, limits)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, ErrDenied
	}
	trust.Writer = append([]byte(nil), trust.Writer...)
	trust.Maintenance = append([]byte(nil), trust.Maintenance...)
	return &Client{http: client, endpoint: u, peer: target, policy: clonePolicy(policy), journal: journal, trust: trust, limits: limits, certificate: leaf}, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) binding(op, id, kind string) Binding {
	return Binding{op, kind, c.policy.Domain, c.policy.Repository, c.policy.Epoch, id, c.peer, c.policy.Self, id, c.repair}
}
func (c *Client) authorized(push bool) error {
	if c.repair != "" && (!validID(c.repair) || !c.policy.Peers[c.peer].Repair) {
		return ErrDenied
	}
	if !certCurrent(c.certificate, time.Now()) {
		return ErrDenied
	}
	if e := c.policy.grant(c.peer, push, time.Now()); e != nil {
		return e
	}
	if push {
		return c.policy.grant(c.peer, false, time.Now())
	}
	return nil
}

type response struct {
	data   []byte
	header http.Header
	status int
}

func (c *Client) request(ctx context.Context, op, id, mode, method, resource string, payload []byte, max int, submitted *atomic.Int64) (response, error) {
	var result response
	for attempt := 0; attempt < c.limits.Attempts; attempt++ {
		if e := ctx.Err(); e != nil {
			return result, e
		}
		if e := c.authorized(mode == "push"); e != nil {
			return result, e
		}
		deadline := time.Unix(c.policy.Peers[c.peer].ExpiresUnix, 0)
		if c.certificate.NotAfter.Before(deadline) {
			deadline = c.certificate.NotAfter
		}
		bounded, cancel := context.WithDeadline(ctx, deadline)
		address := c.endpoint.String() + "/v1/" + c.policy.Domain + "/generations/" + id + "/" + resource
		req, e := http.NewRequestWithContext(bounded, method, address, bytes.NewReader(payload))
		if e != nil {
			cancel()
			return result, ErrProtocol
		}
		req.Header.Set("Outpost-Operation", op)
		if c.policy.RequiredRevision != 0 {
			req.Header.Set("Outpost-Required-Revision", strconv.FormatUint(c.policy.RequiredRevision, 10))
		}
		req.Header.Set("Outpost-Mode", mode)
		if c.repair != "" {
			req.Header.Set("Outpost-Repair", c.repair)
		}
		window := mode == "push" && method == http.MethodPost && (resource == "missing" || resource == "complete")
		if window {
			req.Header.Set(windowHeader, "1")
		}
		if mode == "push" && method == http.MethodPut && resource == "catalog" && c.policy.Peers[c.peer].History {
			req.Header.Set("Outpost-History", "1")
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Accept-Encoding", "identity")
		if submitted != nil {
			submitted.Add(int64(len(payload)))
		}
		res, e := c.http.Do(req)
		retry := e != nil
		if e == nil {
			if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 || Identity(res.TLS.PeerCertificates[0]) != c.peer || !certCurrent(res.TLS.PeerCertificates[0], time.Now()) {
				res.Body.Close()
				cancel()
				return result, ErrDenied
			}
			if res.StatusCode == http.StatusOK || window && resource == "complete" && res.StatusCode == http.StatusAccepted {
				if res.ContentLength > int64(max) || res.Header.Get("Content-Encoding") != "" {
					res.Body.Close()
					cancel()
					return result, ErrProtocol
				}
				b, readErr := io.ReadAll(io.LimitReader(res.Body, int64(max)+1))
				res.Body.Close()
				cancel()
				if readErr == nil && len(b) <= max {
					return response{b, res.Header.Clone(), res.StatusCode}, nil
				}
				if len(b) > max {
					return result, ErrProtocol
				}
				retry = true
			} else {
				res.Body.Close()
				cancel()
				switch res.StatusCode {
				case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
					retry = true
				case http.StatusForbidden, http.StatusUnauthorized:
					return result, ErrDenied
				case http.StatusConflict:
					return result, ErrConflict
				case http.StatusPreconditionFailed:
					return result, generation.ErrIncomplete
				case http.StatusInsufficientStorage:
					return result, ErrCapacity
				default:
					return result, ErrProtocol
				}
			}
		} else {
			cancel()
		}
		if retry && attempt+1 < c.limits.Attempts {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 25 * time.Millisecond):
			}
			continue
		}
		return result, ErrUnavailable
	}
	return result, ErrUnavailable
}
func parallel(ctx context.Context, objects []generation.Object, n int, fn func(context.Context, generation.Object) error) error {
	bounded, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan generation.Object)
	var wg sync.WaitGroup
	var once sync.Once
	var first error
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ref := range jobs {
				if e := bounded.Err(); e != nil {
					return
				}
				if e := fn(bounded, ref); e != nil {
					once.Do(func() { first = e; cancel() })
					return
				}
			}
		}()
	}
feed:
	for _, ref := range objects {
		select {
		case jobs <- ref:
		case <-bounded.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if first != nil {
		return first
	}
	return ctx.Err()
}
func (c *Client) getObject(ctx context.Context, op, id, mode string, ref generation.Object) ([]byte, error) {
	r, e := c.request(ctx, op, id, mode, http.MethodGet, "objects/"+ref.ID, nil, ref.Bytes, nil)
	if e != nil {
		return nil, e
	}
	if len(r.data) != ref.Bytes || generation.Hash(r.data) != ref.ID || r.header.Get("ETag") != `"`+ref.ID+`"` {
		return nil, ErrProtocol
	}
	return r.data, nil
}
func (c *Client) Push(ctx context.Context, operation, id string, source *generation.Replica) (Result, error) {
	return c.transfer(ctx, operation, id, source, true)
}
func (c *Client) Pull(ctx context.Context, operation, id string, target *generation.Replica) (Result, error) {
	return c.transfer(ctx, operation, id, target, false)
}

func (c *Client) RepairPush(ctx context.Context, operation, id, token string, source *generation.Replica) (Result, error) {
	if !validID(token) {
		return Result{}, ErrDenied
	}
	copy := *c
	copy.repair = token
	copy.policy = clonePolicy(c.policy)
	copy.policy.ReadbackMaxAgeSeconds = 0
	return copy.transfer(ctx, operation, id, source, true)
}
func (c *Client) RepairPull(ctx context.Context, operation, id, token string, target *generation.Replica) (Result, error) {
	if !validID(token) || target == nil {
		return Result{}, ErrDenied
	}
	if e := target.CheckRepair(ctx, id, token); e != nil {
		return Result{}, e
	}
	copy := *c
	copy.repair = token
	return copy.transfer(ctx, operation, id, target, false)
}

func (c *Client) transfer(ctx context.Context, operation, id string, local *generation.Replica, push bool) (result Result, err error) {
	if !validID(operation) || !validID(id) || local == nil {
		return result, ErrDenied
	}
	t, _ := json.Marshal(c.trust)
	u, _ := json.Marshal(local.Trust())
	if !bytes.Equal(t, u) {
		return result, ErrDenied
	}
	if err = c.authorized(push); err != nil {
		return result, err
	}
	kind := "pull"
	if push {
		kind = "push"
	}
	binding := c.binding(operation, id, kind)
	unlock, e := lockFile(ctx, c.journal.root, ".job-"+jobKey(binding))
	if e != nil {
		return result, e
	}
	defer unlock()
	if _, err = c.journal.Begin(ctx, binding); err != nil {
		return result, err
	}
	var submitted, received, readback atomic.Int64
	counters := func() Counters { return Counters{submitted.Load(), received.Load(), readback.Load()} }
	defer func() {
		result.Counters = counters()
		if err != nil {
			bounded, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = c.journal.Update(bounded, binding, "RETRYABLE", nil, counters())
		}
	}()
	if err = c.journal.Update(ctx, binding, "TRANSFERRING", nil, counters()); err != nil {
		return result, err
	}
	var raw []byte
	localPin := generation.Hash([]byte(Format + "/send/" + jobKey(binding)))
	if push {
		if err = local.Pin(ctx, localPin, id, "generation"); err != nil {
			return result, err
		}
		raw, err = local.Catalog(ctx, id)
		if err != nil {
			return result, err
		}
		if _, err = c.request(ctx, operation, id, kind, http.MethodPut, "catalog", raw, 1024, nil); err != nil {
			return result, err
		}
	} else {
		if _, err = c.request(ctx, operation, id, kind, http.MethodPost, "lease", nil, 1024, nil); err != nil {
			return result, err
		}
		r, e := c.request(ctx, operation, id, kind, http.MethodGet, "catalog", nil, generation.MaxCatalog, nil)
		if e != nil {
			return result, e
		}
		raw = r.data
		if generation.Hash(raw) != id {
			return result, ErrProtocol
		}
		if _, err = generation.VerifyCatalog(raw, c.trust); err != nil {
			return result, err
		}
		if c.repair != "" {
			err = local.RepairCatalogFor(ctx, id, c.repair, raw)
		} else {
			_, err = local.Begin(ctx, raw)
			if errors.Is(err, generation.ErrRollback) && c.policy.Peers[c.peer].History {
				_, err = local.BeginHistorical(ctx, raw)
			}
		}
		if err != nil {
			return result, err
		}
	}
	refs, e := generation.Dependencies(raw, c.trust)
	if e != nil {
		return result, e
	}
	if push {
		r, e := c.request(ctx, operation, id, kind, http.MethodPost, "missing", nil, generation.MaxCatalog, nil)
		if e != nil {
			return result, e
		}
		var missing []generation.Object
		if err = decode(r.data, &missing, generation.MaxCatalog); err != nil {
			return result, err
		}
		expected := map[string]generation.Object{}
		for _, ref := range refs {
			expected[ref.ID] = ref
		}
		seen := map[string]bool{}
		if len(missing) > len(refs) {
			return result, ErrProtocol
		}
		for _, ref := range missing {
			known, ok := expected[ref.ID]
			if !ok || seen[ref.ID] || known != ref {
				return result, ErrProtocol
			}
			seen[ref.ID] = true
		}
		err = parallel(ctx, missing, c.limits.Concurrency, func(ctx context.Context, ref generation.Object) error {
			b, e := local.ReadObject(ctx, id, ref)
			if e != nil {
				return e
			}
			r, e := c.request(ctx, operation, id, kind, http.MethodPut, "objects/"+ref.ID, b, 1024, &submitted)
			if e != nil {
				return e
			}
			var ack struct {
				Object string `json:"object"`
				State  string `json:"state"`
			}
			if e = decode(r.data, &ack, 1024); e != nil || ack.Object != ref.ID || ack.State != "HASH_VERIFIED_DURABLE" {
				return ErrProtocol
			}
			return nil
		})
		if err != nil {
			return result, err
		}
		if err = c.journal.Update(ctx, binding, "VERIFYING", nil, counters()); err != nil {
			return result, err
		}
		receipt, e := c.completeRemote(ctx, binding, len(refs))
		for repaired := 0; c.repair != "" && errors.Is(e, generation.ErrIncomplete) && repaired < len(refs); repaired++ {
			count, err := c.sendRepairMissing(ctx, binding, local, refs, &submitted)
			if err != nil {
				return result, err
			}
			if count == 0 {
				return result, e
			}
			receipt, e = c.completeRemote(ctx, binding, len(refs))
		}
		if e != nil {
			return result, e
		}
		result.TargetReceipt = &receipt
		// A successful status/receipt alone is insufficient. Read back the signed
		// catalog and every physical dependency through the pinned peer route.
		r, e = c.request(ctx, operation, id, kind, http.MethodGet, "catalog", nil, generation.MaxCatalog, nil)
		if e != nil {
			return result, e
		}
		if !bytes.Equal(r.data, raw) {
			return result, ErrProtocol
		}
		readback.Add(int64(len(r.data)))
		var oldest int64
		result.CachedObjects, oldest, err = c.auditObjects(ctx, operation, id, refs, &readback)
		if err != nil {
			return result, err
		}
		result.Receipt = Receipt{Format, c.peer, id, id, operation, "client-full-readback", time.Now().Unix()}
		if result.CachedObjects > 0 {
			result.Receipt.Format = CachedReceiptFormat
			result.Receipt.Verification = "client-cached-readback"
			result.Receipt.ObservedUnix = oldest
		}
	} else {
		missing, e := local.MissingMetadata(ctx, id)
		if c.repair != "" {
			missing, e = local.RepairMissing(ctx, id)
		}
		if e != nil {
			return result, e
		}
		err = parallel(ctx, missing, c.limits.Concurrency, func(ctx context.Context, ref generation.Object) error {
			b, e := c.getObject(ctx, operation, id, kind, ref)
			if e != nil {
				return e
			}
			received.Add(int64(len(b)))
			if c.repair != "" {
				return local.RepairPutFor(ctx, id, ref.ID, c.repair, b)
			}
			return local.Put(ctx, id, ref.ID, b)
		})
		if err != nil {
			return result, err
		}
		if err = c.journal.Update(ctx, binding, "VERIFYING", nil, counters()); err != nil {
			return result, err
		}
		result.Receipt, err = c.completeLocal(ctx, binding, local, len(refs), &received)
		if err != nil {
			return result, err
		}
	}
	if err = c.journal.Update(ctx, binding, "COMPLETE", &result.Receipt, counters()); err != nil {
		return result, err
	}
	if push {
		result.CleanupPending = local.ReleasePin(ctx, localPin) != nil
	} else {
		_, e = c.request(ctx, operation, id, kind, http.MethodDelete, "lease", nil, 1024, nil)
		result.CleanupPending = e != nil
	}
	return result, nil
}

// IsConflict permits callers to keep semantic conflicts out of retry queues.
func IsConflict(err error) bool {
	return errors.Is(err, ErrConflict) || errors.Is(err, generation.ErrConflict) || errors.Is(err, generation.ErrRollback)
}
