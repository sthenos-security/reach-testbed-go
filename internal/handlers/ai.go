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
		log.Printf("ai answer decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Question) == "" || len(req.Question) > 2048 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "answered locally",
	})
}

func AIAgentPlan(w http.ResponseWriter, r *http.Request) {
	var req agentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("ai agent plan decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Task) == "" || len(req.Task) > 2048 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "plan accepted locally",
	})
}

func SafeAIAnswer(w http.ResponseWriter, r *http.Request) {
	var req promptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("safe ai answer decode failed: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.Question) == "" || len(req.Question) > 2048 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if strings.Contains(strings.ToLower(req.Question), "ignore previous") {
		http.Error(w, "unsafe instruction", http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "answered locally",
	})
}
