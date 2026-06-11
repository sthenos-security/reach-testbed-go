package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/reachable/reach-testbed-go/internal/safety"
)

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"host":   host,
		"status": "ping unavailable",
	})
}

func SafeDiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"host":   host,
		"status": "ping unavailable",
	})
}
