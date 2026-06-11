package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type promptRequest struct {
	Question string `json:"question"`
}

type agentRequest struct {
	Task string `json:"task"`
}

func AIAnswer(w http.ResponseWriter, r *http.Request) {
	var req promptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "AIAnswer decode request", err)
		return
	}

	log.Printf("AIAnswer accepted request")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func AIAgentPlan(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "AIAgentPlan decode request", err)
		return
	}

	_ = req
	log.Printf("AIAgentPlan accepted request")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "accepted",
		"mode":   "local",
	})
}

func SafeAIAnswer(w http.ResponseWriter, r *http.Request) {
	var req promptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeBadRequest(w, "SafeAIAnswer decode request", err)
		return
	}
	if strings.Contains(strings.ToLower(req.Question), "ignore previous") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}
