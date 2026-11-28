package storage

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nd4y/outpost/internal/generation"
	"github.com/nd4y/outpost/internal/teststore"
)

func TestSDKSignatureCoversActualConditionalPutLength(t *testing.T) {
	payload := []byte("synthetic signed object")
	var signedLength atomic.Bool
	s := teststore.New(t, teststore.Options{Kind: "s3", Namespace: Hash([]byte("sdk-signing")), MaxObject: 64 << 10,
		Logins: map[string]teststore.Login{"test-worker": {Secret: "ephemeral-test-secret", Token: "ephemeral-token"}},
		Before: func(_ http.ResponseWriter, r *http.Request, _, key string, body []byte) bool {
			if r.Method == http.MethodPut && strings.HasPrefix(key, "part-") {
				var names []string
				for _, field := range strings.Split(r.Header.Get("Authorization"), ",") {
					if value, ok := strings.CutPrefix(strings.TrimSpace(field), "SignedHeaders="); ok {
						names = strings.Split(value, ";")
					}
				}
				t.Logf("SDK signed header names: %v", names)
				if r.ContentLength == int64(len(payload)) && bytes.Equal(body, payload) && r.Header.Get("If-None-Match") == "*" && slices.Contains(names, "content-length") {
					signedLength.Store(true)
				}
			}
			return false
		}})
	b, err := New(profile(s), Credentials{Access: "test-worker", Secret: "ephemeral-test-secret", SessionToken: "ephemeral-token", ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ref := generation.Object{ID: Hash(payload), Bytes: len(payload)}
	if err := b.PutPart(context.Background(), ref, payload); err != nil {
		t.Fatal("independent S3 oracle rejected SDK signed framing", err)
	}
	got, err := b.ReadPart(context.Background(), ref)
	if err != nil || !bytes.Equal(got, payload) || !signedLength.Load() {
		t.Fatal("signed conditional part did not roundtrip", err)
	}
}

func TestSDKIntegrationDoesNotDiscoverCredentials(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "synthetic-ambient-access")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "synthetic-ambient-secret")
	s := teststore.New(t, teststore.Options{Kind: "s3", Namespace: Hash([]byte("explicit-credentials")), MaxObject: 64 << 10})
	if b, err := New(profile(s), Credentials{ExpiresUnix: time.Now().Add(time.Minute).Unix()}, s.Roots); err == nil {
		b.Close()
		t.Fatal("ambient credentials substituted for explicit target credentials")
	}
	if s.Snapshot().Requests != 0 {
		t.Fatal("missing explicit credentials caused endpoint traffic")
	}
}
