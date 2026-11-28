package peer

import (
	"io"
	"net/http"
	"sync/atomic"
)

const objectAlreadyPresentHeader = "Outpost-Object-Already-Present"

// PushedObjectBodyObservation records an application body on the successful
// client request for one object and its matching authenticated peer ACK.
type PushedObjectBodyObservation struct {
	ObservedUnixMillis      int64 `json:"observedUnixMillis"`
	TransportReadBodyBytes  int   `json:"transportReadBodyBytes"`
	AcknowledgedBodyBytes   int   `json:"acknowledgedBodyBytes"`
	ElapsedNanos            int64 `json:"elapsedNanos,omitempty"`
	AlreadyPresentBodyBytes *int  `json:"alreadyPresentBodyBytes,omitempty"`
}

// alreadyPresentBodyBytes accepts only one exact, optional indication from
// the authenticated peer whose object ACK was already validated.
func alreadyPresentBodyBytes(header http.Header, bytes int) *int {
	values := header.Values(objectAlreadyPresentHeader)
	if len(values) == 1 {
		switch values[0] {
		case "true":
			return &bytes
		case "false":
			zero := 0
			return &zero
		}
	}
	return nil
}

type countedPushRequestBody struct {
	io.ReadCloser
	read     atomic.Int64
	replayed atomic.Bool
}

func countPushRequestBody(req *http.Request) *countedPushRequestBody {
	body := &countedPushRequestBody{ReadCloser: req.Body}
	req.Body = body
	if original := req.GetBody; original != nil {
		req.GetBody = func() (io.ReadCloser, error) {
			// Preserve the transport's replay and pacing behavior. A replay
			// makes the bytes of the successful exchange unidentifiable here.
			body.replayed.Store(true)
			return original()
		}
	}
	return body
}

func (b *countedPushRequestBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	return n, err
}

func (b *countedPushRequestBody) completeBytes(expected int) int {
	if b == nil || b.replayed.Load() || b.read.Load() != int64(expected) {
		return 0
	}
	return expected
}
