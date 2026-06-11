package handlers

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/reachable/reach-testbed-go/internal/safety"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v2"
)

func ParseYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeBadRequest(w, "ParseYAML read request", err)
		return
	}

	var decoded map[string]any
	if err := yaml.Unmarshal(body, &decoded); err != nil {
		writeBadRequest(w, "ParseYAML unmarshal request", err)
		return
	}

	_ = json.NewEncoder(w).Encode(decoded)
}

func ParseLanguage(w http.ResponseWriter, r *http.Request) {
	tag := r.URL.Query().Get("tag")
	if !safety.AllowedLanguageTag(tag) {
		http.Error(w, "unsupported language tag", http.StatusBadRequest)
		return
	}

	parsed, err := language.Parse(tag)
	if err != nil {
		log.Printf("ParseLanguage: %v", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	_, _ = w.Write([]byte(parsed.String() + "\n"))
}
