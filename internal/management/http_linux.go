package management

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/nd4y/outpost/internal/command"
	"github.com/nd4y/outpost/internal/control"
	"github.com/nd4y/outpost/internal/peer"
	"github.com/nd4y/outpost/internal/statefile"
	"github.com/nd4y/outpost/internal/storage"
)

type HTTPOptions struct {
	Principals []Principal
	// A relay needs both an explicit recipient grant and matching scopes.
	Relays       map[string][]string
	Origin       string
	Concurrency  int
	Timeout      time.Duration
	ReportMaxAge time.Duration
}
type httpService struct {
	registry               *Registry
	principals             map[string]Principal
	relays                 map[string]map[string]bool
	origin                 string
	timeout, maxAge        time.Duration
	slots, controls, large chan struct{}
}

func Handler(r *Registry, o HTTPOptions) (http.Handler, error) {
	u, e := url.Parse(o.Origin)
	if r == nil || e != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || u.Opaque != "" || o.Concurrency < 1 || o.Concurrency > 8 || o.Timeout < 100*time.Millisecond || o.Timeout > 10*time.Second || o.ReportMaxAge < time.Second || o.ReportMaxAge > 24*time.Hour || len(o.Principals) == 0 || len(o.Principals) > 128 {
		return nil, ErrInvalid
	}
	h := &httpService{registry: r, principals: map[string]Principal{}, relays: map[string]map[string]bool{}, origin: o.Origin, timeout: o.Timeout, maxAge: o.ReportMaxAge, slots: make(chan struct{}, o.Concurrency), controls: make(chan struct{}, 1), large: make(chan struct{}, 1)}
	for _, p := range o.Principals {
		if p.Validate() != nil {
			return nil, ErrInvalid
		}
		if _, ok := h.principals[p.Actor]; ok {
			return nil, ErrInvalid
		}
		p.Roles = append([]string(nil), p.Roles...)
		p.Scopes = append([]Scope(nil), p.Scopes...)
		h.principals[p.Actor] = p
	}
	if len(o.Relays) > 128 {
		return nil, ErrInvalid
	}
	for actor, recipients := range o.Relays {
		if !storage.ID(actor) || len(recipients) == 0 || len(recipients) > 128 {
			return nil, ErrInvalid
		}
		h.relays[actor] = map[string]bool{}
		for _, node := range recipients {
			if !storage.ID(node) || h.relays[actor][node] {
				return nil, ErrInvalid
			}
			h.relays[actor][node] = true
		}
	}
	return h, nil
}

type httpFailure struct {
	Format string `json:"format"`
	Code   string `json:"code"`
}

var errBodyLimit = errors.New("management body limit")

func failHTTP(w http.ResponseWriter, e error) {
	status, code := http.StatusServiceUnavailable, "UNAVAILABLE"
	switch {
	case errors.Is(e, ErrDenied), errors.Is(e, control.ErrDenied):
		status, code = 403, "DENIED"
	case errors.Is(e, errBodyLimit):
		status, code = 413, "INVALID"
	case errors.Is(e, ErrUnavailable):
		status, code = 404, "UNAVAILABLE"
	case errors.Is(e, ErrConflict), errors.Is(e, control.ErrRollback):
		status, code = 409, "CONFLICT"
	case errors.Is(e, ErrInvalid), errors.Is(e, statefile.ErrInvalid):
		status, code = 400, "INVALID"
	case errors.Is(e, ErrCapacity), errors.Is(e, statefile.ErrCapacity):
		status, code = 503, "CAPACITY"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(httpFailure{"outpost-management-error-1", code})
}
func writeHTTP(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// The ordinary decoder rejects unknown fields, but duplicate JSON keys need
// an explicit boundary check before decoding into a typed request.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	tokens := 0
	var walk func(int) error
	walk = func(depth int) error {
		tokens++
		if tokens > 65536 || depth > 32 {
			return ErrInvalid
		}
		token, e := d.Token()
		if e != nil {
			return ErrInvalid
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return ErrInvalid
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}

// Transport JSON permits whitespace and field ordering. Signed documents
// inside it still require their exact canonical bytes at signature validation.
func decodeHTTP(raw []byte, out any, max int) error {
	if len(raw) == 0 || len(raw) > max || uniqueJSON(raw) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func readHTTP(w http.ResponseWriter, r *http.Request, out any, max int) error {
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" {
		return ErrInvalid
	}
	if r.ContentLength > int64(max) {
		return errBodyLimit
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(max)))
	if e != nil {
		var large *http.MaxBytesError
		if errors.As(e, &large) {
			return errBodyLimit
		}
		return ErrInvalid
	}
	if decodeHTTP(raw, out, max) != nil {
		return ErrInvalid
	}
	return nil
}
func (h *httpService) principal(ctx context.Context, r *http.Request) (Principal, error) {
	var p Principal
	if r.TLS == nil || r.TLS.Version < tls.VersionTLS13 || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return p, ErrDenied
	}
	cert := r.TLS.PeerCertificates[0]
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return p, ErrDenied
	}
	actor := peer.Identity(cert)
	if p, ok := h.principals[actor]; ok {
		return p, nil
	}
	return h.registry.NodePrincipal(ctx, actor)
}
func pageQuery(r *http.Request) (int, string, error) {
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil {
		return 0, "", ErrInvalid
	}
	for k, values := range query {
		if k != "cursor" && k != "limit" || len(values) != 1 {
			return 0, "", ErrInvalid
		}
	}
	limit := 64
	if v := query.Get("limit"); query.Has("limit") {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 256 {
			return 0, "", ErrInvalid
		}
		limit = n
	}
	token := query.Get("cursor")
	if len(token) > 512 {
		return 0, "", ErrInvalid
	}
	return limit, token, nil
}
func (h *httpService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	if r.URL.RawPath != "" || r.URL.ForceQuery || r.URL.EscapedPath() != r.URL.Path || r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodPut {
		failHTTP(w, ErrInvalid)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	r = r.WithContext(ctx)
	deadline := time.Now().Add(h.timeout)
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	if r.Method != http.MethodGet && (r.Header.Get("X-Outpost-Request") != "1" || r.Header.Get("Origin") != "" && r.Header.Get("Origin") != h.origin || r.Header.Get("Sec-Fetch-Site") == "cross-site") {
		failHTTP(w, ErrDenied)
		return
	}
	// Stop/command requests have their own slot, independent of report and
	// inventory overload. Bodies and deadlines remain bounded in both lanes.
	slots := h.slots
	if strings.HasPrefix(r.URL.Path, "/v1/config/") || strings.Contains(r.URL.Path, "/configuration") || strings.Contains(r.URL.Path, "/domains/") || strings.HasSuffix(r.URL.Path, "/reports") {
		slots = h.large
	}
	if strings.Contains(r.URL.Path, "/commands") {
		slots = h.controls
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeHTTP(w, 429, httpFailure{"outpost-management-error-1", "BUSY"})
		return
	}
	p, e := h.principal(ctx, r)
	if e != nil {
		failHTTP(w, e)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) == 3 && parts[0] == "v1" && parts[1] == "config" && storage.ID(parts[2]) && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		node := parts[2]
		if p.Actor != node && !h.relays[p.Actor][node] {
			failHTTP(w, ErrDenied)
			return
		}
		recipient, e := h.registry.NodePrincipal(ctx, node)
		if e != nil {
			failHTTP(w, ErrUnavailable)
			return
		}
		tenant := recipient.Scopes[0].Tenant
		for _, scope := range recipient.Scopes {
			if !p.Allows(scope.Tenant, scope.Domain) {
				failHTTP(w, ErrDenied)
				return
			}
		}
		out, e := h.registry.Configuration(ctx, recipient, tenant, node)
		if e != nil {
			failHTTP(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(out.Document)
		return
	}
	if r.URL.RawQuery != "" {
		paged := r.Method == http.MethodGet && (len(parts) == 5 && (parts[4] == "nodes" || parts[4] == "audit") || len(parts) == 9 && (parts[8] == "generations" || parts[8] == "jobs" || parts[8] == "command-status") || len(parts) == 7 && parts[6] == "commands")
		if !paged {
			failHTTP(w, ErrInvalid)
			return
		}
	}
	if len(parts) == 3 && parts[0] == "api" && parts[1] == "v1" && parts[2] == "session" && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		writeHTTP(w, 200, struct {
			Format string   `json:"format"`
			Actor  string   `json:"actor"`
			Roles  []string `json:"roles"`
			Scopes []Scope  `json:"scopes"`
		}{"outpost-management-session-1", p.Actor, p.Roles, p.Scopes})
		return
	}
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "tenants" || !storage.ID(parts[3]) || !p.Allows(parts[3], "") {
		failHTTP(w, ErrDenied)
		return
	}
	tenant := parts[3]
	if len(parts) == 5 && parts[4] == "nodes" && r.Method == http.MethodGet {
		limit, token, e := pageQuery(r)
		if e != nil {
			failHTTP(w, e)
			return
		}
		out, e := h.registry.Nodes(ctx, p, tenant, limit, token, r.URL.Path, h.maxAge)
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if len(parts) == 5 && parts[4] == "audit" && r.Method == http.MethodGet {
		limit, token, e := pageQuery(r)
		if e != nil {
			failHTTP(w, e)
			return
		}
		out, e := h.registry.AuditPage(ctx, p, tenant, limit, token, r.URL.Path)
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if len(parts) == 6 && parts[4] == "operations" && storage.ID(parts[5]) && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		out, e := h.registry.Operation(ctx, p, tenant, parts[5])
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if len(parts) < 7 || parts[4] != "nodes" || !storage.ID(parts[5]) {
		failHTTP(w, ErrUnavailable)
		return
	}
	node := parts[5]
	action := parts[6]
	if len(parts) == 7 && (action == "enrollment" || action == "revocation") && r.Method == http.MethodPut && r.URL.RawQuery == "" {
		var input SignedMutation
		if e := readHTTP(w, r, &input, 2*MaxEnrollment); e != nil {
			failHTTP(w, e)
			return
		}
		enrollment, e := VerifyEnrollment(input.Document, h.registry.owner)
		if e != nil || enrollment.Node != node || enrollment.Tenant != tenant || enrollment.Revoked != (action == "revocation") {
			failHTTP(w, ErrInvalid)
			return
		}
		out, e := h.registry.ApplyEnrollment(ctx, p, input.Operation, input.Reason, input.Document, input.Expected)
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if len(parts) == 7 && action == "reports" && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		if !p.Role("node") || p.Actor != node {
			failHTTP(w, ErrDenied)
			return
		}
		var input struct {
			Document []byte `json:"document"`
		}
		if e := readHTTP(w, r, &input, MaxReport*4/3+4096); e != nil {
			failHTTP(w, e)
			return
		}
		out, e := h.registry.PublishReport(ctx, p.Actor, tenant, node, input.Document)
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if action == "configuration" && r.URL.RawQuery == "" {
		if len(parts) == 7 && r.Method == http.MethodGet {
			out, e := h.registry.Configuration(ctx, p, tenant, node)
			if e != nil {
				failHTTP(w, e)
				return
			}
			writeHTTP(w, 200, out)
			return
		}
		if len(parts) == 7 && r.Method == http.MethodPut || len(parts) == 8 && parts[7] == "preview" && r.Method == http.MethodPost {
			if !p.Role("owner") {
				failHTTP(w, ErrDenied)
				return
			}
			var input SignedMutation
			if e := readHTTP(w, r, &input, control.MaxConfig*4/3+4096); e != nil {
				failHTTP(w, e)
				return
			}
			if r.Method == http.MethodPost {
				out, e := h.registry.PreviewConfiguration(ctx, p, tenant, node, input)
				if e != nil {
					failHTTP(w, e)
					return
				}
				writeHTTP(w, 200, out)
			} else {
				out, e := h.registry.ApplyConfiguration(ctx, p, tenant, node, input)
				if e != nil {
					failHTTP(w, e)
					return
				}
				writeHTTP(w, 200, out)
			}
			return
		}
	}
	if len(parts) == 9 && action == "domains" && storage.ID(parts[7]) && r.Method == http.MethodGet {
		domain, kind := parts[7], parts[8]
		if kind != "report" && kind != "generations" && kind != "jobs" && kind != "command-status" {
			failHTTP(w, ErrUnavailable)
			return
		}
		if kind == "report" && r.URL.RawQuery != "" {
			failHTTP(w, ErrInvalid)
			return
		}
		view, e := h.registry.Report(ctx, p, tenant, node, domain, h.maxAge)
		if e != nil {
			failHTTP(w, e)
			return
		}
		if kind == "report" {
			writeHTTP(w, 200, view)
			return
		}
		out, e := h.reportPage(p, r, view, kind)
		if e != nil {
			failHTTP(w, e)
			return
		}
		writeHTTP(w, 200, out)
		return
	}
	if action == "commands" {
		if len(parts) == 7 && r.Method == http.MethodPost && r.URL.RawQuery == "" {
			if !oneOfRole(p, "owner", "operator", "recovery") {
				failHTTP(w, ErrDenied)
				return
			}
			var input command.Request
			if e := readHTTP(w, r, &input, command.MaxRequest); e != nil {
				failHTTP(w, e)
				return
			}
			out, e := h.registry.AdmitCommand(ctx, p, tenant, node, input)
			if e != nil {
				failHTTP(w, e)
				return
			}
			status := http.StatusAccepted
			if out.State != "ADMITTED" {
				status = http.StatusOK
			}
			writeHTTP(w, status, out)
			return
		}
		if len(parts) == 7 && r.Method == http.MethodGet {
			limit, token, e := pageQuery(r)
			if e != nil {
				failHTTP(w, e)
				return
			}
			if !r.URL.Query().Has("limit") {
				limit = 32
			}
			out, e := h.registry.CommandPage(ctx, p, tenant, node, limit, token, r.URL.Path)
			if e != nil {
				failHTTP(w, e)
				return
			}
			writeHTTP(w, 200, out)
			return
		}
		if len(parts) == 9 && storage.ID(parts[7]) && parts[8] == "receipt" && r.Method == http.MethodPut && r.URL.RawQuery == "" {
			if !p.Role("node") || p.Actor != node {
				failHTTP(w, ErrDenied)
				return
			}
			var input struct {
				Document []byte `json:"document"`
			}
			if e := readHTTP(w, r, &input, command.MaxAck*4/3+4096); e != nil {
				failHTTP(w, e)
				return
			}
			out, e := h.registry.AcknowledgeCommand(ctx, p, tenant, node, parts[7], input.Document)
			if e != nil {
				failHTTP(w, e)
				return
			}
			writeHTTP(w, 200, out)
			return
		}
		failHTTP(w, ErrUnavailable)
		return
	}
	failHTTP(w, ErrUnavailable)
}
func (h *httpService) reportPage(p Principal, r *http.Request, view ReportView, kind string) (any, error) {
	limit, token, e := pageQuery(r)
	if e != nil {
		return nil, e
	}
	binding := cursorBinding(p, r.URL.Path+"\x00"+view.DocumentDigest)
	cur, e := h.registry.readCursor(token, binding)
	if e != nil {
		return nil, e
	}
	offset := 0
	if token != "" {
		n, e := strconv.Atoi(cur.Position)
		if e != nil || n < 0 || n > 4096 || cur.Revision != view.Sequence {
			return nil, ErrConflict
		}
		offset = n
	}
	total := len(view.Generations)
	if kind == "jobs" {
		total = len(view.Jobs)
	}
	if kind == "command-status" {
		total = len(view.Commands)
	}
	if offset > total {
		return nil, ErrConflict
	}
	end := min(offset+limit, total)
	next := ""
	if end < total {
		next = h.registry.writeCursor(view.Sequence, strconv.Itoa(end), binding)
	}
	if kind == "generations" {
		return struct {
			Format         string       `json:"format"`
			ReportSequence uint64       `json:"reportSequence"`
			ObservedUnix   int64        `json:"observedUnix"`
			State          string       `json:"state"`
			InventoryState string       `json:"inventoryState"`
			Items          []Generation `json:"items"`
			NextCursor     string       `json:"nextCursor,omitempty"`
		}{"outpost-management-generations-1", view.Sequence, view.ObservedUnix, view.State, inventoryState(view.InventoryState), view.Generations[offset:end], next}, nil
	}
	if kind == "command-status" {
		format := "outpost-management-command-status-1"
		if view.Format == "outpost-management-report-view-3" {
			format = "outpost-management-command-status-2"
		}
		items := view.Commands[offset:end]
		if items == nil {
			items = []CommandObservation{}
		}
		return struct {
			Format         string               `json:"format"`
			ReportSequence uint64               `json:"reportSequence"`
			ObservedUnix   int64                `json:"observedUnix"`
			State          string               `json:"state"`
			Items          []CommandObservation `json:"items"`
			NextCursor     string               `json:"nextCursor,omitempty"`
		}{format, view.Sequence, view.ObservedUnix, view.State, items, next}, nil
	}
	return struct {
		Format         string `json:"format"`
		ReportSequence uint64 `json:"reportSequence"`
		ObservedUnix   int64  `json:"observedUnix"`
		State          string `json:"state"`
		Items          []Job  `json:"items"`
		NextCursor     string `json:"nextCursor,omitempty"`
	}{"outpost-management-jobs-1", view.Sequence, view.ObservedUnix, view.State, view.Jobs[offset:end], next}, nil
}

func inventoryState(value string) string {
	if value == "" {
		return "UNKNOWN"
	}
	return value
}
