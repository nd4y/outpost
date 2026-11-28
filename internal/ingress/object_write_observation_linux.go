package ingress

import (
	"bytes"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// ObjectWriteObservation describes one direct ingress PUT and the matching
// authenticated readback. Its count is the application body read by net/http.
type ObjectWriteObservation struct {
	PutStartedUnixMillis       int64 `json:"putStartedUnixMillis"`
	PutAcknowledgedUnixMillis  int64 `json:"putAcknowledgedUnixMillis"`
	VerifiedUnixMillis         int64 `json:"verifiedUnixMillis"`
	TransportReadPutBodyBytes  int   `json:"transportReadPutBodyBytes"`
	AlreadyPresentPutBodyBytes int   `json:"alreadyPresentPutBodyBytes"`
}

type objectWriteAttempt struct {
	started, acknowledged time.Time
	read                  atomic.Int64
	replayed              atomic.Bool
}

type countedObjectWriteBody struct {
	io.ReadCloser
	count *atomic.Int64
}

func (b countedObjectWriteBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
	return n, err
}

func (a *objectWriteAttempt) track(req *http.Request, now time.Time) {
	a.started = now
	req.Body = countedObjectWriteBody{req.Body, &a.read}
	if original := req.GetBody; original != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			a.replayed.Store(true)
			return original()
		}
	}
}

func (a *objectWriteAttempt) confirmed(raw []byte, expected int, now time.Time) (ObjectWriteObservation, bool) {
	if a == nil || expected <= 0 || a.replayed.Load() || a.read.Load() != int64(expected) ||
		a.started.IsZero() || a.acknowledged.IsZero() {
		return ObjectWriteObservation{}, false
	}
	sample := ObjectWriteObservation{
		PutStartedUnixMillis: a.started.UnixMilli(), PutAcknowledgedUnixMillis: a.acknowledged.UnixMilli(),
		VerifiedUnixMillis: now.UnixMilli(), TransportReadPutBodyBytes: expected,
	}
	// The native receiver always writes this explicit boolean. Preserve the
	// legacy success path for other accepted replies without deriving a count.
	switch {
	case bytes.Equal(bytes.TrimSpace(raw), []byte(`{"created":false}`)):
		sample.AlreadyPresentPutBodyBytes = expected
	case bytes.Equal(bytes.TrimSpace(raw), []byte(`{"created":true}`)):
	default:
		return ObjectWriteObservation{}, false
	}
	return sample, sample.PutStartedUnixMillis > 0 && sample.PutStartedUnixMillis <= sample.PutAcknowledgedUnixMillis &&
		sample.PutAcknowledgedUnixMillis <= sample.VerifiedUnixMillis
}
