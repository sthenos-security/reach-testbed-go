package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestDiagnosticPingRejectsCommandInjection(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/diagnostics/ping?host=localhost;touch+/tmp/reach-owned", nil)
	rec := httptest.NewRecorder()

	DiagnosticPing(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if strings.Contains(rec.Body.String(), "touch") {
		t.Fatalf("response leaked injected command: %q", rec.Body.String())
	}
}

func TestSafeDiagnosticPingDoesNotExecutePing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/diagnostics/safe-ping?host=localhost", nil)
	rec := httptest.NewRecorder()

	SafeDiagnosticPing(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "diagnostic accepted\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestFetchToolDoesNotFetchRequestURL(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = io.WriteString(w, "payload")
	}))
	defer server.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/fetch-tool?url="+server.URL, nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if called {
		t.Fatal("FetchTool fetched the request-derived URL")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "tool fetch disabled\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestAIAnswerUsesGenericDecodeError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ai/answer", strings.NewReader("{"))
	rec := httptest.NewRecorder()

	AIAnswer(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if rec.Body.String() != "bad request\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}

func TestSupportExportRedactsPII(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/support/export", nil)
	rec := httptest.NewRecorder()

	SupportExport(rec, req)

	body := rec.Body.String()
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
		regexp.MustCompile(`\d{4}-\d{2}-\d{2}`),
		regexp.MustCompile(`\d{13,19}`),
		regexp.MustCompile(`[^,\s]+@[^,\s]+`),
		regexp.MustCompile(`\+\d[-\d]+`),
	} {
		if pattern.MatchString(body) {
			t.Fatalf("response contains PII pattern %q: %q", pattern.String(), body)
		}
	}
}

func TestCloudTokensDoNotExposeSecretValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/cloud-tokens", nil)
	rec := httptest.NewRecorder()

	CloudTokens(rec, req)

	body := rec.Body.String()
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`g[h]p_[A-Za-z0-9_]{20,}`),
		regexp.MustCompile(`A[K]IA[0-9A-Z]{16}`),
	} {
		if pattern.MatchString(body) {
			t.Fatalf("response contains secret pattern %q: %q", pattern.String(), body)
		}
	}
}
