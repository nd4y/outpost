package ingress

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/filekit"
	"github.com/nd4y/outpost/internal/storage"
)

func TestIngressObjectWriteObservationRequiresUnambiguousCompleteBody(t *testing.T) {
	body := []byte("ciphertext")
	request, err := http.NewRequest(http.MethodPut, "https://fixture.invalid", bytes.NewReader(body))
	must(t, err)
	start := time.Now()
	var attempt objectWriteAttempt
	attempt.track(request, start)
	attempt.acknowledged = start.Add(time.Millisecond)
	if _, ok := attempt.confirmed([]byte(`{"created":false}`), len(body), start.Add(2*time.Millisecond)); ok {
		t.Fatal("declared length was treated as a consumed body")
	}
	raw, err := io.ReadAll(request.Body)
	must(t, err)
	must(t, request.Body.Close())
	if !bytes.Equal(raw, body) || request.ContentLength != int64(len(body)) {
		t.Fatal("tracking changed HTTP data or framing")
	}
	verified := start.Add(2 * time.Millisecond)
	for _, missing := range []string{`{}`, `{"created":null}`, `{"created":true,"created":false}`} {
		if _, ok := attempt.confirmed([]byte(missing), len(body), verified); ok {
			t.Fatal("inexact acknowledgement produced an observation", missing)
		}
	}
	sample, ok := attempt.confirmed([]byte(`{"created":false}`), len(body), verified)
	if !ok || sample.TransportReadPutBodyBytes != len(body) || sample.AlreadyPresentPutBodyBytes != len(body) ||
		sample.PutStartedUnixMillis != start.UnixMilli() || sample.VerifiedUnixMillis != verified.UnixMilli() {
		t.Fatal("the exact successful body was not measured", sample)
	}
	replay, err := request.GetBody()
	must(t, err)
	raw, err = io.ReadAll(replay)
	must(t, err)
	must(t, replay.Close())
	if !bytes.Equal(raw, body) {
		t.Fatal("tracking changed transport replay")
	}
	if _, ok = attempt.confirmed([]byte(`{"created":true}`), len(body), verified); ok {
		t.Fatal("transport replay was attributed to an exact successful request")
	}
}

type ingressAckRecorder struct {
	*httptest.ResponseRecorder
	underlying http.ResponseWriter
}

func (w ingressAckRecorder) Unwrap() http.ResponseWriter { return w.underlying }

func TestIngressObjectWriteObservationRequiresAuthenticatedReadback(t *testing.T) {
	var corruptReadback, legacyAck atomic.Bool
	f := network(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/objects/") {
				if legacyAck.Load() && r.Method == http.MethodPut {
					// The real handler must set deadlines on the live connection.
					accepted := ingressAckRecorder{httptest.NewRecorder(), w}
					next.ServeHTTP(accepted, r)
					for key, values := range accepted.Header() {
						w.Header()[key] = values
					}
					body := accepted.Body.Bytes()
					if accepted.Code == http.StatusOK {
						body = []byte("{}")
					}
					w.Header().Set("Content-Length", strconv.Itoa(len(body)))
					w.WriteHeader(accepted.Code)
					_, _ = w.Write(body)
					return
				}
				if corruptReadback.Load() && r.Method == http.MethodGet {
					_, _ = w.Write([]byte("corrupt"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	})
	body := []byte("opaque object for direct measurement")
	ref := filekit.Object{ID: storage.Hash(body), Bytes: len(body)}
	var observations []ObjectWriteObservation
	f.client.ObserveObjectWrite = func(sample ObjectWriteObservation) { observations = append(observations, sample) }
	ctx := context.Background()
	created, err := f.client.Write(ctx, ref, body)
	must(t, err)
	if !created || len(observations) != 1 || observations[0].TransportReadPutBodyBytes != len(body) ||
		observations[0].AlreadyPresentPutBodyBytes != 0 {
		t.Fatal("new staged object did not produce exact evidence", observations)
	}
	created, err = f.client.Write(ctx, ref, body)
	must(t, err)
	if created || len(observations) != 2 || observations[1].AlreadyPresentPutBodyBytes != len(body) {
		t.Fatal("accepted existing object did not produce exact evidence", observations)
	}
	legacyAck.Store(true)
	created, err = f.client.Write(ctx, ref, body)
	must(t, err)
	if created || len(observations) != 2 {
		t.Fatal("legacy success semantics changed or unproven counts appeared", observations)
	}
	legacyAck.Store(false)
	corruptReadback.Store(true)
	if _, err = f.client.Write(ctx, ref, body); !errors.Is(err, ErrProtocol) || len(observations) != 2 {
		t.Fatal("readback failure produced a successful observation", err, observations)
	}
}

func TestIngressObjectWriteObservationPreservesPacedCancellation(t *testing.T) {
	f := network(t, nil)
	body := bytes.Repeat([]byte{0x3a}, 256<<10)
	ref := filekit.Object{ID: storage.Hash(body), Bytes: len(body)}
	var observations []ObjectWriteObservation
	f.client.ObserveObjectWrite = func(sample ObjectWriteObservation) { observations = append(observations, sample) }
	slow, err := storage.NewHTTPBodyBudget(64 << 10)
	must(t, err)
	f.client.SetPayloadBudget(slow)
	bounded, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	_, err = f.client.Write(bounded, ref, body)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || len(observations) != 0 {
		t.Fatal("paced incomplete PUT ignored cancellation or created evidence", err, observations)
	}

	paced, err := storage.NewHTTPBodyBudget(1 << 20)
	must(t, err)
	f.client.SetPayloadBudget(paced)
	start := time.Now()
	created, err := f.client.Write(t.Context(), ref, body)
	must(t, err)
	if time.Since(start) < 400*time.Millisecond {
		t.Fatal("observed PUT and verified readback bypassed body pacing")
	}
	if !created || len(observations) != 1 || observations[0].TransportReadPutBodyBytes != len(body) {
		t.Fatal("retry did not measure exactly the new successful PUT", observations)
	}
}
