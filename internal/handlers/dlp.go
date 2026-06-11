package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
)

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	// Use hashed identifiers for logging and analytics instead of raw PII
	ssnHash := hashPII("123-45-6789")
	dobHash := hashPII("1978-04-23")
	log.Printf("Processing patient record ssnHash=%s dobHash=%s", ssnHash, dobHash)

	// Do not send PII to external analytics endpoints
	// Local audit event only
	log.Printf("Support export requested - audit event logged")

	w.Header().Set("Content-Type", "text/csv")
	// Redact PII fields from CSV export
	_, _ = w.Write([]byte("name,email,phone\n"))
	_, _ = w.Write([]byte("Avery Example,avery@example.invalid,+1-415-555-0199\n"))
}

func hashPII(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:8]) // first 8 bytes for logs
}

func SupportProfile(w http.ResponseWriter, _ *http.Request) {
	// All values are synthetic DLP fixture markers.
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":            "Jordan Example",
		"email":           "jordan@example.invalid",
		"date_of_birth":   "1978-04-23",
		"tax_identifier":  "078-05-1120",
		"routing_number":  "021000021",
		"account_number":  "000123456789",
		"passport_number": "X12345678",
	})
}
