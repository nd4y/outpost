package peer

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
)

func TestPushedObjectBodyCountsActualReadsAndOmitsReplay(t *testing.T) {
	payload := []byte("known object body")
	req, err := http.NewRequest(http.MethodPut, "https://fixture.invalid/objects", bytes.NewReader(payload))
	must(t, err)
	body := countPushRequestBody(req)
	prefix := make([]byte, 3)
	_, err = io.ReadFull(req.Body, prefix)
	must(t, err)
	if !bytes.Equal(prefix, payload[:3]) || body.completeBytes(len(payload)) != 0 {
		t.Fatal("a planned or partially consumed body was measured as complete")
	}
	out, err := io.ReadAll(req.Body)
	must(t, err)
	must(t, req.Body.Close())
	if !bytes.Equal(out, payload[3:]) || req.ContentLength != int64(len(payload)) || body.completeBytes(len(payload)) != len(payload) {
		t.Fatal("counting changed the actual body or framing")
	}
	replay, err := req.GetBody()
	must(t, err)
	again, err := io.ReadAll(replay)
	must(t, err)
	must(t, replay.Close())
	if !bytes.Equal(again, payload) || body.completeBytes(len(payload)) != 0 {
		t.Fatal("transport replay changed the body or was counted as one known attempt")
	}
}

func TestPeerObjectAlreadyPresentHintIsOptional(t *testing.T) {
	for _, tc := range []struct {
		values []string
		want   int
	}{
		{nil, -1},
		{[]string{""}, -1},
		{[]string{"true,false"}, -1},
		{[]string{"true", "true"}, -1},
		{[]string{"false"}, 0},
		{[]string{"true"}, 163},
	} {
		header := http.Header{}
		for _, value := range tc.values {
			header.Add(objectAlreadyPresentHeader, value)
		}
		got := alreadyPresentBodyBytes(header, 163)
		if tc.want < 0 && got != nil || tc.want >= 0 && (got == nil || *got != tc.want) {
			t.Fatalf("hint %q: got %v, expected %d", tc.values, got, tc.want)
		}
	}
}

func TestPeerObjectObservationMeasuresAcknowledgedRetryUnderMTLS(t *testing.T) {
	f := newFixture(t)
	id, _ := f.seal(t, 1, "")
	var puts, releasedAt atomic.Int64
	var firstStored, retryExisting atomic.Bool
	const ackDelay = 20 * time.Millisecond
	server := f.endpoint(t, f.a, f.policy(f.a, f.b), func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.Method != http.MethodPut || !strings.Contains(req.URL.Path, "/objects/") {
				next.ServeHTTP(w, req)
				return
			}
			attempt := puts.Add(1)
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, req)
			switch attempt {
			case 1:
				firstStored.Store(rec.Code == http.StatusOK && rec.Header().Get(objectAlreadyPresentHeader) == "false")
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case 2:
				retryExisting.Store(rec.Code == http.StatusOK && rec.Header().Get(objectAlreadyPresentHeader) == "true")
				time.Sleep(ackDelay)
				releasedAt.Store(time.Now().UnixMilli())
			default:
				// An older peer sends the same authenticated ACK body without
				// the optional indication. Its PUT must still complete.
				rec.Header().Del(objectAlreadyPresentHeader)
			}
			for name, values := range rec.Header() {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
	})
	client := f.client(t, f.b, f.a, server.URL, f.policy(f.b, f.a))
	client.limits.Concurrency = 1
	client.limits.Attempts = 2
	var samples []PushedObjectBodyObservation
	client.ObservePushedObject = func(sample PushedObjectBodyObservation) { samples = append(samples, sample) }
	_, err := client.Push(testContext, generation.Hash([]byte("measured peer retry")), id, f.b.replica)
	must(t, err)
	if !firstStored.Load() || !retryExisting.Load() || len(samples) < 2 || int64(len(samples))+1 != puts.Load() {
		t.Fatalf("fixture did not separate the lost ACK, retry, and legacy peer: PUTs=%d observations=%d", puts.Load(), len(samples))
	}
	first := samples[0]
	if first.ObservedUnixMillis < releasedAt.Load() || first.ElapsedNanos < ackDelay.Nanoseconds() ||
		first.AlreadyPresentBodyBytes == nil || *first.AlreadyPresentBodyBytes != first.AcknowledgedBodyBytes ||
		first.TransportReadBodyBytes != first.AcknowledgedBodyBytes {
		t.Fatalf("invalid retry observation: %+v", first)
	}
	for _, sample := range samples[1:] {
		if sample.AlreadyPresentBodyBytes != nil || sample.ElapsedNanos <= 0 ||
			sample.TransportReadBodyBytes != sample.AcknowledgedBodyBytes {
			t.Fatalf("legacy acknowledgment inferred presence or lost timing: %+v", sample)
		}
	}
	wrongPeer := f.client(t, f.b, f.c, server.URL, f.policy(f.b, f.c))
	wrongPeer.ObservePushedObject = func(PushedObjectBodyObservation) { t.Error("mismatched mTLS peer produced telemetry") }
	if _, err = wrongPeer.Push(testContext, generation.Hash([]byte("wrong observed peer")), id, f.b.replica); err == nil {
		t.Fatal("mismatched mTLS peer accepted")
	}
}
