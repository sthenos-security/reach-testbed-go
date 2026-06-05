package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/reachable/reach-testbed-go/internal/safety"
)

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "diagnostic accepted",
	})
}

func SafeDiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if !safety.AllowedHostname(host) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "diagnostic accepted",
	})
}
