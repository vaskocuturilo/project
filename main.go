package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"project1/accesstoken"
	"project1/refreshtoken"
	"project1/token"
	"strings"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", login)
	mux.Handle("/verify", accesstoken.Middleware(http.HandlerFunc(verify)))

	mux.HandleFunc("/refresh", refreshtoken.Refresh)

	srv := http.Server{Addr: "localhost:8091", Handler: mux}

	fmt.Printf("The Server running at http://localhost:8091")
	err := srv.ListenAndServe()
	if err != nil {
		return
	}
}

func verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}

	user, ok := accesstoken.GetUserFromContext(r.Context())

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)

	type response struct {
		Message string `json:"message"`
	}

	err := json.NewEncoder(w).Encode(
		response{Message: fmt.Sprintf("Hello, %s!", user.Name)},
	)
	if err != nil {
		return
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}

	authHeader := r.Header.Get("Authorization")

	const basicAuthPrefix = "Basic "

	if authHeader == "" || !strings.HasPrefix(authHeader, basicAuthPrefix) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	payload, err := base64.StdEncoding.DecodeString(authHeader[len(basicAuthPrefix):])

	if err != nil {
		http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
		return
	}

	creds := strings.SplitN(string(payload), ":", 2)

	if len(creds) != 2 {
		http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
		return
	}

	user, err := accesstoken.AuthUser(creds[0], creds[1])

	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	accessToken, err := token.CreateAccessToken(user)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	type response struct {
		AccessToken string `json:"access_token"`
	}

	err = json.NewEncoder(w).Encode(response{AccessToken: accessToken})
	if err != nil {
		return
	}
}
