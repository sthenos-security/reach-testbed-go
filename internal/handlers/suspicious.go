package handlers

import (
	"encoding/json"
	"net/http"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("url")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "fetch disabled",
	})
}

func SuspiciousMarkers(w http.ResponseWriter, _ *http.Request) {
	// Synthetic suspicious-behavior markers only; nothing is executed.
	_, _ = w.Write([]byte("synthetic markers only\n"))
}
