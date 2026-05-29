package main

import (
	"log"
	"net/http"
	"os"

	"github.com/reachable/reach-testbed-go/internal/handlers"
)

func main() {
	mux := http.NewServeMux()
	handlers.Register(mux)

	addr := ":8080"
	if configured := os.Getenv("REACH_TESTBED_ADDR"); configured != "" {
		addr = configured
	}

	log.Printf("reach-testbed-go listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
