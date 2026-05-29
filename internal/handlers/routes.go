package handlers

import "net/http"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /parse-yaml", ParseYAML)
	mux.HandleFunc("POST /parse-language", ParseLanguage)
	mux.HandleFunc("GET /diagnostics/ping", DiagnosticPing)
	mux.HandleFunc("GET /diagnostics/safe-ping", SafeDiagnosticPing)
	mux.HandleFunc("GET /token", ServiceToken)
	mux.HandleFunc("GET /cloud-tokens", CloudTokens)
	mux.HandleFunc("GET /env-token", EnvToken)
	mux.HandleFunc("GET /support/export", SupportExport)
	mux.HandleFunc("GET /support/profile", SupportProfile)
	mux.HandleFunc("POST /ai/answer", AIAnswer)
	mux.HandleFunc("POST /ai/agent-plan", AIAgentPlan)
	mux.HandleFunc("POST /ai/safe-answer", SafeAIAnswer)
	mux.HandleFunc("POST /admin/fetch-tool", FetchTool)
	mux.HandleFunc("GET /admin/suspicious-markers", SuspiciousMarkers)
	mux.HandleFunc("GET /healthz", Healthz)
}

func Healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}
