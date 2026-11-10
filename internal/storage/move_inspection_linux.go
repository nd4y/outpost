package storage

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
)

type MoveStagingAttempt struct {
	Temporary          string `json:"temporary"`
	Digest             string `json:"digest"`
	Bytes              int    `json:"bytes"`
	Phase              string `json:"phase"`
	WriteStartedMillis int64  `json:"writeStartedMillis,omitempty"`
}

type MoveStagingPage struct {
	Bucket    string               `json:"bucket,omitempty"`
	State     string               `json:"state"`
	Attempts  []MoveStagingAttempt `json:"attempts"`
	NextAfter string               `json:"nextAfter,omitempty"`
}

func (b *MoveBook) temporaryName(r MoveRecord, a MoveAttempt) string {
	return "attempt-" + Hash([]byte(MoveBookFormat+"/"+b.o.Scope+"/"+b.o.Profile.ID()+"/"+r.Key+"/"+r.Digest+"/"+a.Nonce))
}

// InspectStaging reads at most one recorded bucket. Even PUBLISHED only
// describes the local attempt. No phase asserts that the temporary object
// exists remotely or that deleting it would be safe.
func (b *MoveBook) InspectStaging(ctx context.Context, after string) (MoveStagingPage, error) {
	if after != "" && !movePrefix(after) {
		return MoveStagingPage{}, ErrDenied
	}
	out := MoveStagingPage{State: "EMPTY", Attempts: []MoveStagingAttempt{}}
	e := b.store.WithLock(ctx, func() error {
		if e := b.guard(ctx); e != nil {
			return e
		}
		h, e := b.header()
		if e != nil {
			return e
		}
		if after != "" && h.Buckets[after] == "" {
			return ErrConflict
		}
		prefixes := slices.Sorted(maps.Keys(h.Buckets))
		i, found := slices.BinarySearch(prefixes, after)
		if found {
			i++
		}
		if i >= len(prefixes) {
			return nil
		}
		out.Bucket = prefixes[i]
		out.State = h.Buckets[out.Bucket]
		if i+1 < len(prefixes) {
			out.NextAfter = out.Bucket
		}
		bucket, e := b.readBucket(out.Bucket)
		if out.State == "ALLOCATING" {
			if errors.Is(e, os.ErrNotExist) || e == nil && len(bucket.Records) == 0 {
				return nil
			}
			return ErrConflict
		}
		if e != nil {
			return e
		}
		for _, id := range slices.Sorted(maps.Keys(bucket.Records)) {
			r := bucket.Records[id]
			for _, a := range r.Attempts {
				out.Attempts = append(out.Attempts, MoveStagingAttempt{Temporary: b.temporaryName(r, a),
					Digest: r.Digest, Bytes: r.Bytes, Phase: a.Phase, WriteStartedMillis: a.WriteStartedMillis})
			}
		}
		return b.guard(ctx)
	})
	if e != nil {
		return MoveStagingPage{}, e
	}
	return out, nil
}

// VerifyMoveStage reads only one generated staging name in this MOVE namespace.
// A successful response with different bytes is distinct from a failed read.
func (b *Backend) VerifyMoveStage(ctx context.Context, a MoveStagingAttempt) (bool, error) {
	name, ok := strings.CutPrefix(a.Temporary, "attempt-")
	if b.profile.WriteMode != WebDAVMoveMode || !ok || !ID(name) || !ID(a.Digest) ||
		a.Bytes < 1 || a.Bytes > b.profile.MaxObjectBytes || a.WriteStartedMillis <= 0 {
		return false, ErrDenied
	}
	data, status, e := b.request(ctx, http.MethodGet, a.Temporary, nil)
	if e != nil {
		return false, e
	}
	if status != http.StatusOK {
		return false, ErrUnsupported
	}
	return len(data) == a.Bytes && Hash(data) == a.Digest, nil
}
