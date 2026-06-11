package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIAnswerDoesNotEchoPrompt(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/ai/answer", bytes.NewBufferString(`{"question":"secret payroll data"}`))
	rec := httptest.NewRecorder()

	AIAnswer(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); strings.Contains(body, "secret payroll data") {
		t.Fatalf("response echoed request content: %q", body)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"status":"accepted"`) {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestParseYAMLReturnsGenericError(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/parse-yaml", bytes.NewBufferString(":\n"))
	rec := httptest.NewRecorder()

	ParseYAML(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if body := rec.Body.String(); body != "bad request\n" {
		t.Fatalf("body = %q, want generic bad request", body)
	}
}

func TestSupportExportRedactsSensitiveFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/support/export", nil)
	rec := httptest.NewRecorder()

	SupportExport(rec, req)

	body := rec.Body.String()
	for _, needle := range []string{"123-45-6789", "1978-04-23", "4111111111111111", "+1-415-555-0199"} {
		if strings.Contains(body, needle) {
			t.Fatalf("export leaked %q in %q", needle, body)
		}
	}
	if !strings.Contains(body, "[redacted]") {
		t.Fatalf("expected redacted values in export, got %q", body)
	}
}

func TestDiagnosticPingDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/diagnostics/ping?host=example.com", nil)
	rec := httptest.NewRecorder()

	DiagnosticPing(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); !strings.Contains(body, "ping disabled") {
		t.Fatalf("body = %q, want disabled response", body)
	}
}

func TestFetchToolDisabled(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/fetch-tool?url=https%3A%2F%2Fexample.com%2Ftool.bin", nil)
	rec := httptest.NewRecorder()

	FetchTool(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := rec.Body.String(); !strings.Contains(body, "fetch disabled") {
		t.Fatalf("body = %q, want disabled response", body)
	}
}
