package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetricsCountCompletedTransfersAndHandleFragmentedLogs(t *testing.T) {
	m := newMetrics(true)
	_, _ = m.Write([]byte("2026/01/01 00:00:00 [12] OUTPOST_TRANS"))
	_, _ = m.Write([]byte("FER recv 24 100\nOUTPOST_TRANSFER send 10 100\nOUTPOST_TRANSFER recv invalid 100\nOUTPOST_TRANSFER del. 0 0\n"))
	if m.receivedFiles.Load() != 1 || m.receivedBytes.Load() != 24 || m.sentFiles.Load() != 1 || m.sentBytes.Load() != 10 || m.lastTransfer.Load() == 0 {
		t.Fatal("completed transfer accounting is incorrect")
	}
	_, _ = m.Write([]byte(strings.Repeat("x", 9000)))
	if len(m.pending) != 0 {
		t.Fatal("log buffer is unbounded")
	}
	m.receiverReady.Store(true)
	response := httptest.NewRecorder()
	m.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(response.Body.String(), "outpost_up 0\n") {
		t.Fatal("NetBird readiness was ignored")
	}
	m.netbirdReady.Store(true)
	response = httptest.NewRecorder()
	m.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{"outpost_up 1\n", "outpost_rsync_transferred_bytes_total{direction=\"receive\"} 24\n", "outpost_storage_statfs_success", "# TYPE outpost_rsync_transferred_files_total counter"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("missing %s", want)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("metrics response is cacheable")
	}
}

func TestMetricsRestrictRoutesAndMethods(t *testing.T) {
	m := newMetrics(false)
	for _, test := range []struct {
		method, path string
		status       int
	}{{"GET", "/", 404}, {"POST", "/metrics", 405}, {"HEAD", "/metrics", 200}} {
		w := httptest.NewRecorder()
		m.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
		if w.Code != test.status {
			t.Errorf("%s %s: %d", test.method, test.path, w.Code)
		}
		if test.method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD returned body")
		}
	}
}
