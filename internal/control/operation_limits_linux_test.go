package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/upload"
)

func TestSignedOperationWindowKeepsRequestBudgetAndLegacyCanonicalBytes(t *testing.T) {
	c, owner := configFixture(t)
	legacy, err := Sign(c, owner)
	must(t, err)
	if bytes.Contains(legacy, []byte("operationMillis")) || c.Limits.OperationTimeout() != time.Second {
		t.Fatal("omitted operation window changed legacy configuration or budget")
	}
	for _, value := range []int64{1000, upload.DefaultAttemptMillis + 1, 6 * 60 * 60 * 1000, upload.MaxAttemptMillis} {
		long := c
		long.Limits.OperationMillis = value
		raw, err := Sign(long, owner)
		must(t, err)
		verified, err := Verify(raw, owner.Public().(ed25519.PublicKey), c.Node)
		must(t, err)
		if verified.Limits.AttemptMillis != c.Limits.AttemptMillis || verified.Limits.OperationTimeout() != time.Duration(value)*time.Millisecond {
			t.Fatal("operation window changed request timeout")
		}
		alteredConfig := verified
		alteredConfig.Limits.OperationMillis = value - 1
		altered, err := json.Marshal(alteredConfig)
		must(t, err)
		if _, err := Verify(altered, owner.Public().(ed25519.PublicKey), c.Node); err == nil {
			t.Fatal("unsigned operation-window change was accepted")
		}
	}
	for _, value := range []int64{-1, 1, 999, upload.MaxAttemptMillis + 1, int64(^uint64(0) >> 1)} {
		bad := c
		bad.Limits.OperationMillis = value
		if _, err := Sign(bad, owner); err == nil {
			t.Fatal("invalid operation duration signed", value)
		}
	}
	bad := c
	bad.Limits.OperationMillis = upload.MaxAttemptMillis
	bad.Limits.AttemptMillis = upload.DefaultAttemptMillis + 1
	if _, err := Sign(bad, owner); err == nil {
		t.Fatal("long operation expanded short request ceiling")
	}
	// The explicit budget cannot detach work from an earlier parent deadline.
	c.Limits.OperationMillis = upload.MaxAttemptMillis
	parent, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	work, stop := context.WithTimeout(parent, c.Limits.OperationTimeout())
	defer stop()
	select {
	case <-work.Done():
		if !errors.Is(work.Err(), context.DeadlineExceeded) {
			t.Fatal(work.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("long operation ignored its parent deadline")
	}
	c.Limits.OperationMillis = 0
	again, err := Sign(c, owner)
	must(t, err)
	if !bytes.Equal(legacy, again) {
		t.Fatal("returning to omitted window changed legacy canonical bytes")
	}
}
