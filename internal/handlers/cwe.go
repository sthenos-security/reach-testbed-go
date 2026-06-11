package handlers

import (
	"log"
	"net/http"

	"github.com/reachable/reach-testbed-go/internal/safety"
)

func DiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	log.Printf("Diagnostic ping request for host: %s", host)

	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Diagnostic endpoint - validation only, no command execution
	_, _ = w.Write([]byte("diagnostic validation passed\n"))
}

func SafeDiagnosticPing(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	log.Printf("Safe diagnostic ping request for host: %s", host)

	if !safety.AllowedHostname(host) {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}

	// Diagnostic endpoint - validation only, no command execution
	_, _ = w.Write([]byte("diagnostic validation passed\n"))
}
