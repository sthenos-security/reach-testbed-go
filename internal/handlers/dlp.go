package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	log.Printf("Processing patient export (PII redacted)")

	w.Header().Set("Content-Type", "text/csv")
	_, _ = w.Write([]byte("status\n"))
	_, _ = w.Write([]byte("export_complete\n"))
}

func SupportProfile(w http.ResponseWriter, _ *http.Request) {
	// All values are synthetic DLP fixture markers — redacted.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":            "Jordan Example",
		"email":           "jordan@example.invalid",
		"date_of_birth":   "REDACTED",
		"tax_identifier":  "REDACTED",
		"routing_number":  "REDACTED",
		"account_number":  "REDACTED",
		"passport_number": "REDACTED",
	})
}
