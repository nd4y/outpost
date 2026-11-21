package storage

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

const restoreQuery = "restore="
const MaxArchiveParts = 32768

var archiveClassName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
var restoredUntil = regexp.MustCompile(`^ongoing-request="false", *expiry-date="([^"]+)"$`)
var archiveCurrency = regexp.MustCompile(`^[A-Z]{3}$`)

type ArchivePolicy struct {
	Class                string       `json:"class"`
	Tier                 string       `json:"tier"`
	Days                 int          `json:"days"`
	MinimumWindowSeconds int64        `json:"minimumWindowSeconds"`
	MaxParts             int          `json:"maxParts"`
	MaxBytes             int64        `json:"maxBytes"`
	Quote                ArchiveQuote `json:"quote"`
}

type ArchiveQuote struct {
	Currency       string `json:"currency"`
	RequestMicros  int64  `json:"requestMicros"`
	GiBMicros      int64  `json:"gibMicros"`
	MaxBatchMicros int64  `json:"maxBatchMicros"`
}

func (q ArchiveQuote) valid() bool {
	return archiveCurrency.MatchString(q.Currency) && q.RequestMicros >= 0 && q.RequestMicros <= 1_000_000_000 &&
		q.GiBMicros >= 0 && q.GiBMicros <= 1_000_000_000 && q.MaxBatchMicros > 0
}

func (q ArchiveQuote) partMicros(bytes int) int64 {
	const gib = 1 << 30
	// A physical part is bounded to 8 MiB. Round the data charge up per part.
	return q.RequestMicros + (int64(bytes)*q.GiBMicros+gib-1)/gib
}

func (p ArchivePolicy) Validate() error {
	if !archiveClassName.MatchString(p.Class) || p.Class == "STANDARD" ||
		(p.Tier != "Bulk" && p.Tier != "Standard" && p.Tier != "Expedited") ||
		p.Days < 1 || p.Days > 30 || p.MinimumWindowSeconds < 1 || p.MinimumWindowSeconds >= int64(p.Days)*86400 ||
		p.MaxParts < 1 || p.MaxParts > MaxArchiveParts || p.MaxBytes < 1 || p.MaxBytes > int64(MaxArchiveParts)*MaxPhysical || !p.Quote.valid() {
		return ErrDenied
	}
	return nil
}

type ArchivePart struct {
	Object      generation.Object `json:"object"`
	State       string            `json:"state"`
	Metadata    bool              `json:"metadata"`
	ExpiresUnix int64             `json:"expiresUnix,omitempty"`
}

type ArchiveProgress struct {
	Parts                   []ArchivePart `json:"parts"`
	NeedsRequest            int           `json:"needsRequest"`
	NeedsRequestBytes       int64         `json:"needsRequestBytes"`
	RequestsAcknowledged    int           `json:"requestsAcknowledged"`
	Ready                   bool          `json:"ready"`
	EarliestExpiryUnix      int64         `json:"earliestExpiryUnix,omitempty"`
	Currency                string        `json:"currency"`
	RemainingEstimateMicros int64         `json:"remainingEstimateMicros"`
	BatchEstimateMicros     int64         `json:"batchEstimateMicros"`
}

type archiveReply struct {
	bytes int64
	class string
	state string
}

func (*archiveReply) handles(method string, status int) bool {
	return method == http.MethodHead && status == http.StatusOK || method == http.MethodPost &&
		(status == http.StatusOK || status == http.StatusAccepted || status == http.StatusConflict)
}

func (r *archiveReply) read(ctx context.Context, method string, response *http.Response, budget *HTTPBodyBudget, traffic *requestTraffic) error {
	if method == http.MethodHead {
		class := response.Header.Values("X-Amz-Storage-Class")
		state := response.Header.Values("X-Amz-Restore")
		if len(class) > 1 || len(state) > 1 || response.Header.Get("Content-Encoding") != "" {
			return ErrIntegrity
		}
		r.bytes = response.ContentLength
		r.class = response.Header.Get("X-Amz-Storage-Class")
		r.state = response.Header.Get("X-Amz-Restore")
		return nil
	}
	if response.StatusCode != http.StatusConflict {
		return nil
	}
	const maxError = 4096
	raw, err := io.ReadAll(io.LimitReader(traffic.response(budget.response(ctx, response.Body)), maxError+1))
	var detail struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
	}
	if err == nil && len(raw) <= maxError && xml.Unmarshal(raw, &detail) == nil && detail.Code == "RestoreAlreadyInProgress" {
		return nil
	}
	return ErrConflict
}

func (r archiveReply) observation(part generation.Object, policy ArchivePolicy, now time.Time) (ArchivePart, error) {
	result := ArchivePart{Object: part}
	if r.bytes != int64(part.Bytes) {
		return result, ErrIntegrity
	}
	if r.class == "" || r.class == "STANDARD" {
		if r.state != "" {
			return result, ErrIntegrity
		}
		result.State = "ONLINE"
		return result, nil
	}
	if r.class != policy.Class {
		return result, ErrUnsupported
	}
	switch r.state {
	case "":
		result.State = "NEEDS_REQUEST"
	case `ongoing-request="true"`:
		result.State = "PENDING"
	default:
		match := restoredUntil.FindStringSubmatch(r.state)
		if match == nil {
			return result, ErrIntegrity
		}
		expiry, err := http.ParseTime(match[1])
		if err != nil || expiry.Unix() <= 0 {
			return result, ErrIntegrity
		}
		result.ExpiresUnix = expiry.Unix()
		switch {
		case !expiry.After(now):
			result.State = "EXPIRED"
		case expiry.Unix()-now.Unix() < policy.MinimumWindowSeconds:
			result.State = "EXPIRING"
		default:
			result.State = "AVAILABLE"
		}
	}
	return result, nil
}

func (b *Backend) requestArchive(ctx context.Context, part generation.Object, policy ArchivePolicy) error {
	payload, err := xml.Marshal(struct {
		XMLName xml.Name `xml:"RestoreRequest"`
		Days    int      `xml:"Days"`
		Tier    string   `xml:"GlacierJobParameters>Tier"`
	}{Days: policy.Days, Tier: policy.Tier})
	if err != nil {
		return err
	}
	_, _, err = b.requestWith(ctx, http.MethodPost, "part-"+part.ID, payload, requestOptions{archive: &archiveReply{}})
	return err
}

// RetrieveArchive inspects the complete admitted part set before initiating any
// retrieval. Zero maxRequests is read-only. HEAD is repeated on every invocation,
// including restart after a lost POST reply or expiration of a temporary copy.
// The caller must bind parts to a signed catalog and trusted part map first.
func (b *Backend) RetrieveArchive(ctx context.Context, policy ArchivePolicy, parts []generation.Object, hot map[string]bool, maxRequests int) (ArchiveProgress, error) {
	var result ArchiveProgress
	if b.profile.Kind != "s3" || policy.Validate() != nil || maxRequests < 0 || maxRequests > policy.MaxParts {
		return result, ErrDenied
	}
	if len(parts) == 0 || len(parts) > policy.MaxParts {
		return result, ErrCapacity
	}
	var total int64
	previous := ""
	for _, part := range parts {
		if !ID(part.ID) || part.ID <= previous || part.Bytes < 1 || part.Bytes > b.profile.MaxObjectBytes {
			return result, ErrIntegrity
		}
		previous = part.ID
		total += int64(part.Bytes)
	}
	if total > policy.MaxBytes {
		return result, ErrCapacity
	}
	result.Currency = policy.Quote.Currency
	ready := true
	for _, part := range parts {
		var reply archiveReply
		_, _, err := b.requestWith(ctx, http.MethodHead, "part-"+part.ID, nil, requestOptions{archive: &reply})
		if err != nil {
			return result, err
		}
		entry, err := reply.observation(part, policy, time.Now())
		if err != nil {
			return result, err
		}
		entry.Metadata = hot[part.ID]
		if entry.Metadata && entry.State != "ONLINE" {
			return result, ErrUnsupported
		}
		if entry.State == "NEEDS_REQUEST" || entry.State == "EXPIRED" {
			cost := policy.Quote.partMicros(part.Bytes)
			if result.NeedsRequest < maxRequests {
				result.BatchEstimateMicros += cost
			}
			result.RemainingEstimateMicros += cost
			result.NeedsRequest++
			result.NeedsRequestBytes += int64(part.Bytes)
		}
		ready = ready && (entry.State == "AVAILABLE" || entry.State == "ONLINE")
		if entry.State != "EXPIRED" && entry.ExpiresUnix > 0 && (result.EarliestExpiryUnix == 0 || result.EarliestExpiryUnix > entry.ExpiresUnix) {
			result.EarliestExpiryUnix = entry.ExpiresUnix
		}
		result.Parts = append(result.Parts, entry)
	}
	result.Ready = ready && (result.EarliestExpiryUnix == 0 || result.EarliestExpiryUnix-time.Now().Unix() >= policy.MinimumWindowSeconds)
	if result.BatchEstimateMicros > policy.Quote.MaxBatchMicros {
		return result, ErrCapacity
	}
	for i := range result.Parts {
		if result.RequestsAcknowledged == maxRequests {
			break
		}
		part := &result.Parts[i]
		if part.State != "NEEDS_REQUEST" && part.State != "EXPIRED" {
			continue
		}
		if err := b.requestArchive(ctx, part.Object, policy); err != nil {
			return result, err
		}
		part.State, part.ExpiresUnix = "REQUEST_ACCEPTED", 0
		result.RequestsAcknowledged++
		result.NeedsRequest--
		result.NeedsRequestBytes -= int64(part.Object.Bytes)
		result.RemainingEstimateMicros -= policy.Quote.partMicros(part.Object.Bytes)
	}
	return result, nil
}
