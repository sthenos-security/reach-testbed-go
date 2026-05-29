package handlers

import (
	"encoding/json"
	"net/http"
	"os"
)

func ServiceToken(w http.ResponseWriter, _ *http.Request) {
	token := os.Getenv("REACH_TESTBED_SERVICE_TOKEN")
	if token == "" {
		http.Error(w, "token not configured", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("configured\n"))
}

func CloudTokens(w http.ResponseWriter, _ *http.Request) {
	token := os.Getenv("REACH_TESTBED_CLOUD_TOKEN")
	if token == "" {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "not configured"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "configured"})
}

func EnvToken(w http.ResponseWriter, _ *http.Request) {
	token := os.Getenv("REACH_TESTBED_SERVICE_TOKEN")
	if token == "" {
		http.Error(w, "token not configured", http.StatusServiceUnavailable)
		return
	}

	_, _ = w.Write([]byte("configured\n"))
}
