package ingress

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/storage"
)

const stagedInventoryPageSize = 64
const maxStagedInventoryPage = 2*MaxDocument + 128*stagedInventoryPageSize + 1024

type stagedInventory struct {
	epoch   string
	objects []filekit.Object
}

type stagedInventoryPage struct {
	stagingOrigin
	Epoch   string           `json:"epoch"`
	Start   int              `json:"start"`
	Objects []filekit.Object `json:"objects"`
}

type stagedCursor struct {
	epoch  string
	offset int
}

type automaticStaging struct {
	origins []string
	cursors map[string]stagedCursor
	capture string
	next    int
	running bool
}

func newAutomaticStaging(routes *StagingRoutes) automaticStaging {
	var staging automaticStaging
	for id, endpoint := range routes.Origins {
		if endpoint != "" && routes.AutomaticPeers[id] {
			staging.origins = append(staging.origins, id)
		}
	}
	slices.Sort(staging.origins)
	return staging
}

func stagingBinding(intent Intent) string {
	intent.Authority, intent.Ingress, intent.Signature = "", "", nil
	raw, _ := json.Marshal(intent)
	return storage.Hash(raw)
}

func (s *Session) inventoryPage(ctx context.Context, epoch, offset string) (stagedInventoryPage, error) {
	var page stagedInventoryPage
	start, err := strconv.Atoi(offset)
	if err != nil || strconv.Itoa(start) != offset || start < 0 || start > s.intent.MaxObjects ||
		epoch == "" && start != 0 || epoch != "" && !storage.ID(epoch) {
		return page, ErrDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err = s.guard(ctx); err != nil {
		return page, err
	}
	if s.state.Acknowledged {
		return page, ErrDenied
	}
	if s.stagedInventory == nil {
		// A reopened session may enumerate its durable files in a different
		// order. A new epoch tells recipients to start that scan at zero.
		var nonce [32]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return page, err
		}
		s.stagedInventory = &stagedInventory{epoch: hex.EncodeToString(nonce[:]), objects: make([]filekit.Object, 0, len(s.refs))}
		for _, ref := range s.refs {
			s.stagedInventory.objects = append(s.stagedInventory.objects, filekit.Object{ID: ref.ID, Bytes: ref.Bytes})
		}
	}
	inventory := s.stagedInventory
	if epoch != inventory.epoch {
		start = 0
	}
	if start > len(inventory.objects) {
		return page, ErrConflict
	}
	end := min(start+stagedInventoryPageSize, len(inventory.objects))
	return stagedInventoryPage{
		stagingOrigin: stagingOrigin{Authority: s.state.Authority, Intent: s.state.Intent},
		Epoch:         inventory.epoch, Start: start, Objects: slices.Clone(inventory.objects[start:end]),
	}, nil
}

func (g *Registry) readStagedInventory(ctx context.Context, target Intent, origin string, cursor stagedCursor) (stagedInventoryPage, error) {
	var page stagedInventoryPage
	headers := http.Header{}
	headers.Set("Outpost-Capture", stagingBinding(target))
	headers.Set("Outpost-Staged-Epoch", cursor.epoch)
	headers.Set("Outpost-Staged-Offset", strconv.Itoa(cursor.offset))
	raw, err := g.readStagingDocument(ctx, origin, route(target)+"/staged-inventory", headers, maxStagedInventoryPage)
	if err != nil {
		return page, err
	}
	if decodeReply(raw, &page) != nil || !storage.ID(page.Epoch) || len(page.Objects) > stagedInventoryPageSize {
		return page, ErrProtocol
	}
	expected := 0
	if cursor.epoch == page.Epoch {
		expected = cursor.offset
	}
	if page.Start != expected || page.Start+len(page.Objects) > target.MaxObjects {
		return page, ErrProtocol
	}
	seen := make(map[string]bool, len(page.Objects))
	for _, ref := range page.Objects {
		if !validObject(ref) || seen[ref.ID] {
			return page, ErrProtocol
		}
		seen[ref.ID] = true
	}
	i, _, err := g.stagingPeer(target, page.stagingOrigin)
	if err != nil || i.Ingress != origin {
		return page, ErrDenied
	}
	return page, nil
}

func (g *Registry) readStagingDocument(ctx context.Context, origin, path string, headers http.Header, limit int) ([]byte, error) {
	return g.readStagingResponse(ctx, origin, path, headers, "application/json", limit)
}

func (g *Registry) readStagingResponse(ctx context.Context, origin, path string, headers http.Header, media string, limit int) ([]byte, error) {
	h, u, err := peer.AuthenticatedHTTP(g.options.Staging.Origins[origin], g.options.Certificate, g.options.Roots, g.authority.Ingress, origin, g.options.Limits)
	if err != nil {
		return nil, err
	}
	defer h.CloseIdleConnections()
	u.Path = path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		req.Header[name] = values
	}
	req.Header.Set("Accept-Encoding", "identity")
	res, err := h.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.TLS == nil || len(res.TLS.VerifiedChains) == 0 || len(res.TLS.PeerCertificates) == 0 {
		return nil, ErrDenied
	}
	leaf := res.TLS.PeerCertificates[0]
	if peer.Identity(leaf) != origin || time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, ErrDenied
	}
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent:
		return nil, os.ErrNotExist
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, ErrDenied
	default:
		return nil, ErrUnavailable
	}
	if res.ContentLength > int64(limit) || res.Header.Get("Content-Encoding") != "" || res.Header.Get("Content-Type") != media {
		return nil, ErrProtocol
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit || !time.Now().Before(leaf.NotAfter) {
		return nil, ErrProtocol
	}
	return raw, ctx.Err()
}

// advanceAutomaticStaging is entered with the registry lock held. Network
// reads run outside that lock and storage remains bound to the original intent.
func (g *Registry) advanceAutomaticStaging(ctx context.Context, target Intent) (bool, error) {
	staging := &g.stagedPull
	if len(staging.origins) == 0 || staging.running {
		g.mu.Unlock()
		return false, nil
	}
	select {
	case g.stageImports <- struct{}{}:
		defer func() { <-g.stageImports }()
	default:
		g.mu.Unlock()
		return false, nil
	}
	if staging.capture != target.Operation {
		staging.capture, staging.cursors, staging.next = target.Operation, make(map[string]stagedCursor), 0
	}
	origin := staging.origins[staging.next]
	staging.next = (staging.next + 1) % len(staging.origins)
	cursor := staging.cursors[origin]
	raw := bytes.Clone(g.state.Intent)
	staging.running = true
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		staging.running = false
		g.mu.Unlock()
	}()
	page, err := g.readStagedInventory(ctx, target, origin, cursor)
	if err != nil {
		return false, err
	}
	var missing filekit.Object
	next := stagedCursor{epoch: page.Epoch, offset: page.Start}
	g.mu.Lock()
	err = g.withStagingSession(ctx, raw, func(s *Session) error {
		if s.state.Complete || len(s.state.Catalog) != 0 {
			return ErrConflict
		}
		for _, ref := range page.Objects {
			next.offset++
			if !s.has(generation.Object{ID: ref.ID, Bytes: ref.Bytes}) {
				missing = ref
				break
			}
		}
		return nil
	})
	g.mu.Unlock()
	if err != nil {
		return false, err
	}
	if missing.ID != "" {
		if err = g.importStaged(ctx, target, raw, page.stagingOrigin, nil, missing, false); err != nil {
			return false, err
		}
	}
	g.mu.Lock()
	staging.cursors[origin] = next
	g.mu.Unlock()
	return len(page.Objects) != 0, nil
}
