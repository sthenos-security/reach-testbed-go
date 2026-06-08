package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiagnosticPingRejectsCommandInjectionShape(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/diagnostics/ping?host=127.0.0.1%3Bid", nil)
	rec := httptest.NewRecorder()

	DiagnosticPing(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid host") {
		t.Fatalf("expected generic invalid host response, got %q", rec.Body.String())
	}
}

func TestSafeDiagnosticPingDoesNotExecuteCommand(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/diagnostics/safe-ping?host=example.com", nil)
	rec := httptest.NewRecorder()

	SafeDiagnosticPing(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if strings.Contains(rec.Body.String(), "PING") {
		t.Fatalf("expected non-executing status response, got %q", rec.Body.String())
	}
}

func TestFetchToolDoesNotFetchUserURL(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/fetch-tool?url="+server.URL, nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if called {
		t.Fatal("FetchTool made an outbound request to the user-supplied URL")
	}
	if !strings.Contains(rec.Body.String(), "tool fetch disabled") {
		t.Fatalf("expected disabled fetch response, got %q", rec.Body.String())
	}
}
