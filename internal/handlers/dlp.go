package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	log.Printf("Processing support export with redacted fields")

	w.Header().Set("Content-Type", "text/csv")
	_, _ = w.Write([]byte("name,record_status\n"))
	_, _ = w.Write([]byte("Avery Example,redacted\n"))
}

func SupportProfile(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":          "Jordan Example",
		"record_status": "redacted",
	})
}
