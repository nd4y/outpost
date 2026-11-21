package storage

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

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
	budget.request(req)
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
