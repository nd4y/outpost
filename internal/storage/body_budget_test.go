package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"
)

type shortBodyReads struct{ io.Reader }

func (r shortBodyReads) Read(p []byte) (int, error) {
	return r.Reader.Read(p[:min(len(p), bodyBudgetQuantum/4)])
}

func TestHTTPBodyBudgetCarriesShortReadsWithoutRefund(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reads int
	}{
		{name: "one-quantum", reads: 4},
		{name: "cancel-with-prepaid-bytes", reads: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget, err := NewHTTPBodyBudget(64 << 10)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			body := bytes.NewReader(make([]byte, bodyBudgetQuantum*2))
			reader := budget.PaceResponse(ctx, shortBodyReads{body})
			buf := make([]byte, bodyBudgetQuantum)
			n, err := reader.Read(buf)
			if n != bodyBudgetQuantum/4 || err != nil {
				t.Fatalf("first partial read: %d %v", n, err)
			}
			// Another grant moved the schedule. A short read must use its
			// existing allowance without reducing or reserving this delay.
			later := budget.next.Add(time.Minute)
			budget.next = later
			for read := 1; read < tc.reads; read++ {
				n, err = reader.Read(buf)
				if n != bodyBudgetQuantum/4 || err != nil || !budget.next.Equal(later) {
					t.Fatalf("prepaid read %d changed the shared schedule: %d %v", read, n, err)
				}
			}
			cancel()
			n, err = reader.Read(buf)
			if n != 0 || !errors.Is(err, context.Canceled) || body.Len() != 2*bodyBudgetQuantum-tc.reads*(bodyBudgetQuantum/4) {
				t.Fatalf("cancelled reader consumed prepaid data: %d %v", n, err)
			}
		})
	}
}

func TestHTTPBodyBudgetCloseCancelsReplayWaitingForAllowance(t *testing.T) {
	budget, err := NewHTTPBodyBudget(64 << 10)
	if err != nil {
		t.Fatal(err)
	}
	// Put the next reservation outside this test's lifetime.
	budget.next = time.Now().Add(time.Minute)
	req, err := http.NewRequest(http.MethodPut, "https://storage.invalid", bytes.NewReader([]byte("body")))
	if err != nil {
		t.Fatal(err)
	}
	budget.PaceRequest(req)
	defer req.Body.Close()
	replay, err := req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := replay.Read(make([]byte, 32))
		done <- result{n, err}
	}()
	if err := replay.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case read := <-done:
		if read.n != 0 || !errors.Is(read.err, context.Canceled) {
			t.Fatal("closed replay consumed body", read)
		}
	case <-time.After(time.Second):
		t.Fatal("closing replay did not interrupt blocked read")
	}
	if req.ContentLength != 4 {
		t.Fatal("pacer changed request framing")
	}
}
