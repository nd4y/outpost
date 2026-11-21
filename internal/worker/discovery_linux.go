package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

const inventoryFormat = "outpost-inventory-1"
const discoveryFormat = "outpost-discovery-1"
const maxInventory = 64 << 10

type inventoryReply struct {
	Format      string                      `json:"format"`
	Domain      string                      `json:"domain"`
	Repository  string                      `json:"repository"`
	Epoch       uint64                      `json:"epoch"`
	Rule        string                      `json:"rule"`
	Generations []generation.InventoryEntry `json:"generations"`
}
type DiscoveryRoute struct {
	Phase       string `json:"phase"`
	ErrorCode   string `json:"errorCode,omitempty"`
	Generations int    `json:"generations"`
	CheckedUnix int64  `json:"checkedUnix"`
}
type DiscoveryStatus struct {
	Format   string                    `json:"format"`
	Revision uint64                    `json:"configurationRevision"`
	Routes   map[string]DiscoveryRoute `json:"routes"`
}

func currentPeer(s *tls.ConnectionState, id string) bool {
	if s == nil || s.Version < tls.VersionTLS13 || len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
		return false
	}
	leaf := s.PeerCertificates[0]
	now := time.Now()
	return peer.Identity(leaf) == id && !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func (w *Worker) certificateCurrent() bool {
	leaf, e := x509.ParseCertificate(w.cert.Certificate[0])
	if e != nil {
		return false
	}
	now := time.Now()
	return !now.Before(leaf.NotBefore) && now.Before(leaf.NotAfter)
}
func validInventory(entries []generation.InventoryEntry) bool {
	if len(entries) > generation.MaxGenerations {
		return false
	}
	seen := map[string]bool{}
	var previous uint64
	for _, entry := range entries {
		if !storage.ID(entry.Generation) || seen[entry.Generation] || entry.Sequence <= previous {
			return false
		}
		seen[entry.Generation] = true
		previous = entry.Sequence
	}
	return true
}
func (w *Worker) serveInventory(out http.ResponseWriter, r *http.Request, domain string) {
	w.serveDiscovery(out, r, domain, false)
}
func (w *Worker) serveDiscovery(out http.ResponseWriter, r *http.Request, domain string, repair bool) {
	if r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path != r.URL.EscapedPath() {
		http.Error(out, "denied", 403)
		return
	}
	remote := peer.Identity(r.TLS.PeerCertificates[0])
	if !currentPeer(r.TLS, remote) || !w.certificateCurrent() {
		http.Error(out, "denied", 403)
		return
	}
	w.mu.Lock()
	v := w.active
	if v == nil || v.ctx.Err() != nil || v.cfg.Active(time.Now()) != nil {
		w.mu.Unlock()
		http.Error(out, "inactive", 503)
		return
	}
	if required, e := strconv.ParseUint(r.Header.Get("Outpost-Required-Revision"), 10, 64); e == nil && required > v.cfg.Revision {
		if _, known := v.cfg.NodeByID(remote); known {
			w.mu.Unlock()
			out.Header().Set("Retry-After", "1")
			http.Error(out, "configuration pending", 503)
			return
		}
	}
	d, ok := v.cfg.DomainByID(domain)
	local := v.domains[domain]
	allowed := false
	for _, rule := range v.cfg.Replication {
		direction := !repair && rule.Mode == "pull" && rule.From == w.node && rule.To == remote || repair && rule.Repair && rule.Mode == "push" && rule.To == w.node && rule.From == remote
		if rule.Domain == domain && direction && rule.ID(d.Trust) == r.Header.Get("Outpost-Replication") {
			allowed = true
			break
		}
	}
	if !ok || !allowed || local == nil || v.paused(domain, "") {
		w.mu.Unlock()
		http.Error(out, "denied", 403)
		return
	}
	select {
	case v.metadata <- struct{}{}:
	default:
		w.mu.Unlock()
		out.Header().Set("Retry-After", "1")
		http.Error(out, "busy", 503)
		return
	}
	defer func() { <-v.metadata }()
	v.requests.Add(1)
	w.mu.Unlock()
	defer v.requests.Done()
	ctx, cleanup, e := w.requestContext(out, r, v)
	if e != nil {
		http.Error(out, "unavailable", 503)
		return
	}
	defer cleanup()
	var raw []byte
	if repair {
		var needs []generation.RepairNeed
		needs, e = local.replica.RepairNeeds(ctx)
		if e == nil {
			raw, e = json.Marshal(repairNeedsReply{repairNeedsFormat, domain, d.Trust.Repository, d.Trust.Epoch, r.Header.Get("Outpost-Replication"), needs})
		}
	} else {
		var entries []generation.InventoryEntry
		entries, e = local.replica.Inventory(ctx)
		if e == nil {
			raw, e = json.Marshal(inventoryReply{inventoryFormat, domain, d.Trust.Repository, d.Trust.Epoch, r.Header.Get("Outpost-Replication"), entries})
		}
	}
	if e != nil || ctx.Err() != nil {
		http.Error(out, "unavailable", 503)
		return
	}
	if e != nil || len(raw) > maxInventory {
		http.Error(out, "capacity", 507)
		return
	}
	out.Header().Set("Content-Type", "application/json")
	out.Header().Set("Cache-Control", "no-store")
	out.Header().Set("X-Content-Type-Options", "nosniff")
	out.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	_, _ = out.Write(raw)
}
func (w *Worker) inventory(ctx context.Context, v *view, rule control.Replication) ([]generation.InventoryEntry, error) {
	d, ok := v.cfg.DomainByID(rule.Domain)
	local := v.domains[rule.Domain]
	if !ok || local == nil || rule.Executor() != w.node {
		return nil, ErrDenied
	}
	if rule.Mode == "push" {
		return local.replica.Inventory(ctx)
	}
	raw, e := w.discoveryRequest(ctx, v, rule, "inventory")
	if e != nil {
		return nil, e
	}
	var reply inventoryReply
	if storage.Decode(raw, &reply, maxInventory) != nil || reply.Format != inventoryFormat || reply.Domain != rule.Domain || reply.Repository != d.Trust.Repository || reply.Epoch != d.Trust.Epoch || reply.Rule != rule.ID(d.Trust) || !validInventory(reply.Generations) {
		return nil, peer.ErrProtocol
	}
	return reply.Generations, nil
}
func (w *Worker) discoveryRequest(ctx context.Context, v *view, rule control.Replication, resource string) ([]byte, error) {
	d, ok := v.cfg.DomainByID(rule.Domain)
	if !ok {
		return nil, ErrDenied
	}
	node, ok := v.cfg.NodeByID(rule.Peer())
	if !ok || !w.certificateCurrent() {
		return nil, ErrDenied
	}
	h, u, e := peer.AuthenticatedHTTP(node.Endpoint, w.cert, w.roots, w.node, node.ID, peer.Limits{Concurrency: 1, Timeout: time.Duration(v.cfg.Limits.AttemptMillis) * time.Millisecond, Attempts: 1})
	if e != nil {
		return nil, e
	}
	defer h.CloseIdleConnections()
	u.Path += "/v1/" + rule.Domain + "/" + resource
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("Outpost-Replication", rule.ID(d.Trust))
	req.Header.Set("Outpost-Required-Revision", strconv.FormatUint(rule.PeerRevision, 10))
	req.Header.Set("Accept-Encoding", "identity")
	res, e := h.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if !currentPeer(res.TLS, node.ID) {
		return nil, ErrDenied
	}
	if res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusUnauthorized {
		return nil, ErrDenied
	}
	if res.StatusCode != http.StatusOK {
		return nil, peer.ErrUnavailable
	}
	if res.ContentLength > maxInventory || res.Header.Get("Content-Encoding") != "" {
		return nil, peer.ErrProtocol
	}
	raw, e := io.ReadAll(io.LimitReader(res.Body, maxInventory+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > maxInventory || !currentPeer(res.TLS, node.ID) {
		return nil, peer.ErrProtocol
	}
	return raw, nil
}

func (w *Worker) DiscoveryStatus(ctx context.Context) (DiscoveryStatus, error) {
	var s DiscoveryStatus
	if e := w.check(ctx); e != nil {
		return s, e
	}
	e := w.state.WithLock(ctx, func() error { var e error; s, e = w.discoveryState(); return e })
	return s, e
}
func (w *Worker) discoveryState() (DiscoveryStatus, error) {
	s := DiscoveryStatus{Format: discoveryFormat, Routes: map[string]DiscoveryRoute{}}
	raw, e := w.state.Read("discovery.json")
	if errors.Is(e, os.ErrNotExist) {
		return s, nil
	}
	if e != nil {
		return s, e
	}
	if storage.Decode(raw, &s, 1<<20) != nil || s.Format != discoveryFormat || s.Routes == nil || len(s.Routes) > 256 {
		return s, ErrDenied
	}
	for id, r := range s.Routes {
		if !storage.ID(id) || r.Generations < 0 || r.Generations > generation.MaxGenerations || r.CheckedUnix < 0 || r.CheckedUnix > time.Now().Unix() || (r.Phase != "PENDING" && r.Phase != "DISCOVERED" && r.Phase != "RETRY_WAIT" && r.Phase != "BLOCKED") {
			return s, ErrDenied
		}
	}
	return s, nil
}
func (w *Worker) recordDiscovery(ctx context.Context, v *view, rule control.Replication, count int, result error) error {
	d, _ := v.cfg.DomainByID(rule.Domain)
	id := rule.ID(d.Trust)
	return w.recordDiscoveryID(ctx, v, id, count, result)
}
func (w *Worker) recordDiscoveryID(ctx context.Context, v *view, id string, count int, result error) error {
	return w.state.WithLock(ctx, func() error {
		s, e := w.discoveryState()
		if e != nil {
			return e
		}
		if s.Revision != v.cfg.Revision {
			return ErrDenied
		}
		entry := DiscoveryRoute{Phase: "DISCOVERED", Generations: count, CheckedUnix: time.Now().Unix(), ErrorCode: errorCode(result)}
		if result != nil {
			entry.Phase = "RETRY_WAIT"
			if blocked(entry.ErrorCode) {
				entry.Phase = "BLOCKED"
			}
		}
		old, exists := s.Routes[id]
		if exists && old.Phase == entry.Phase && old.ErrorCode == entry.ErrorCode && old.Generations == count && entry.CheckedUnix-old.CheckedUnix < 30 {
			return nil
		}
		s.Routes[id] = entry
		raw, e := json.Marshal(s)
		if e != nil {
			return e
		}
		return w.state.Write("discovery.json", raw)
	})
}

func (w *Worker) resetDiscovery(ctx context.Context, v *view) error {
	return w.state.WithLock(ctx, func() error {
		s, e := w.discoveryState()
		if e != nil {
			return e
		}
		if s.Revision > v.cfg.Revision {
			return ErrDenied
		}
		next := DiscoveryStatus{Format: discoveryFormat, Revision: v.cfg.Revision, Routes: map[string]DiscoveryRoute{}}
		for _, raw := range v.cfg.Uploads {
			id := storage.Hash(raw)
			r, ok := s.Routes[id]
			if !ok {
				r.Phase = "PENDING"
			}
			next.Routes[id] = r
		}
		for _, rule := range v.cfg.Replication {
			if rule.Executor() != w.node {
				continue
			}
			d, _ := v.cfg.DomainByID(rule.Domain)
			id := rule.ID(d.Trust)
			r, ok := s.Routes[id]
			if !ok {
				r.Phase = "PENDING"
			}
			next.Routes[id] = r
		}
		prior, _ := json.Marshal(s)
		raw, e := json.Marshal(next)
		if e != nil {
			return e
		}
		if string(prior) == string(raw) {
			return nil
		}
		return w.state.Write("discovery.json", raw)
	})
}
func (w *Worker) admitDiscovered(ctx context.Context, v *view, rule control.Replication, entries []generation.InventoryEntry) error {
	if !validInventory(entries) {
		return peer.ErrProtocol
	}
	d, _ := v.cfg.DomainByID(rule.Domain)
	jobs := make([]control.Job, 0, len(entries))
	for _, item := range entries {
		jobs = append(jobs, rule.Job(d.Trust, item.Generation))
	}
	if rule.Repair {
		if e := w.admitDerived(ctx, v, jobs); e != nil {
			return e
		}
		jobs = nil
		needs, e := w.repairNeeds(ctx, v, rule)
		if e != nil {
			return e
		}
		healthy := map[string]uint64{}
		for _, item := range entries {
			healthy[item.Generation] = item.Sequence
		}
		for _, need := range needs {
			if healthy[need.Generation] == need.Sequence {
				jobs = append(jobs, rule.RepairJob(d.Trust, need.Generation, need.Token))
			}
		}
	}
	return w.admitDerived(ctx, v, jobs)
}
func (w *Worker) admitDerived(ctx context.Context, v *view, jobs []control.Job) error {
	s, e := w.Status(ctx)
	if e != nil {
		return e
	}
	changed := false
	for _, j := range jobs {
		old, ok := s.Jobs[j.Operation]
		if !ok || old.Phase == "WITHDRAWN" || old.Binding != binding(j) {
			changed = true
			break
		}
	}
	if !changed {
		return nil
	}
	return w.update(ctx, func(s *Status) error {
		for _, j := range jobs {
			if !v.autonomy.Permits(j) || j.Executor != w.node {
				return ErrDenied
			}
			old, ok := s.Jobs[j.Operation]
			if ok && old.Binding != binding(j) {
				return peer.ErrConflict
			}
			if !ok {
				if len(s.Jobs) >= MaxJobs {
					return ErrCapacity
				}
				old = JobState{Job: j, Binding: binding(j), Phase: "QUEUED"}
			}
			if old.Phase == "WITHDRAWN" {
				old.Phase = "QUEUED"
				old.NextMillis = 0
				old.ErrorCode = ""
			}
			s.Jobs[j.Operation] = old
		}
		return nil
	})
}

// Discovery has its own bounded workers so an unavailable source does not
// stop already queued transfers. The view joins all of them before closing.
func (w *Worker) discover(v *view) error {
	rules := []control.Replication{}
	for _, r := range v.cfg.Replication {
		if r.Executor() == w.node && !v.paused(r.Domain, "") {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 && len(v.cfg.Uploads) == 0 {
		return nil
	}
	for v.ctx.Err() == nil {
		work := make(chan control.Replication, len(rules))
		for _, r := range rules {
			work <- r
		}
		close(work)
		var group sync.WaitGroup
		failures := make(chan error, v.cfg.Limits.Parallel)
		for n := 0; n < v.cfg.Limits.Parallel; n++ {
			group.Add(1)
			go func() {
				defer group.Done()
				for rule := range work {
					if v.ctx.Err() != nil {
						return
					}
					ctx, cancel := context.WithTimeout(v.ctx, time.Duration(v.cfg.Limits.AttemptMillis)*time.Millisecond)
					entries, e := w.inventory(ctx, v, rule)
					if e == nil {
						e = w.admitDiscovered(ctx, v, rule, entries)
					}
					cancel()
					if v.ctx.Err() != nil {
						return
					}
					if e = w.recordDiscovery(v.ctx, v, rule, len(entries), e); e != nil {
						failures <- e
						v.cancel()
						return
					}
				}
			}()
		}
		group.Wait()
		close(failures)
		if e := <-failures; e != nil {
			return e
		}
		if e := w.discoverUploads(v); e != nil {
			return e
		}
		select {
		case <-v.ctx.Done():
			return nil
		case <-time.After(time.Duration(v.cfg.Limits.PollSeconds) * time.Second):
		}
	}
	return nil
}
