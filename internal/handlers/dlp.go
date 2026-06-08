package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

func SupportExport(w http.ResponseWriter, _ *http.Request) {
	log.Printf("Processing support export with redacted identifiers")

	w.Header().Set("Content-Type", "text/csv")
	_, _ = w.Write([]byte("name,email,ssn,phone,card_number,last4\n"))
	_, _ = w.Write([]byte("Avery Example,[redacted],[redacted],[redacted],[redacted],[redacted]\n"))
}

func SupportProfile(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name":            "Jordan Example",
		"email":           "[redacted]",
		"date_of_birth":   "[redacted]",
		"tax_identifier":  "[redacted]",
		"routing_number":  "[redacted]",
		"account_number":  "[redacted]",
		"passport_number": "[redacted]",
	})
}
