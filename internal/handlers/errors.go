package handlers

import (
	"log"
	"net/http"
)

func writeBadRequest(w http.ResponseWriter, operation string, err error) {
	if err != nil {
		log.Printf("%s: %v", operation, err)
	}
	http.Error(w, "bad request", http.StatusBadRequest)
}
