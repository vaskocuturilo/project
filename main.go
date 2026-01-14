package main

import (
	"fmt"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /login", login)
	mux.HandleFunc("GET /hello", hello)

	srv := http.Server{Addr: "localhost:8091", Handler: mux}

	fmt.Printf("The Server running at http://localhost:8091")
	err := srv.ListenAndServe()
	if err != nil {
		return
	}
}

func hello(w http.ResponseWriter, r *http.Request) {}

func login(w http.ResponseWriter, r *http.Request) {}
