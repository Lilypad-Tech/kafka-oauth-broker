package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var (
	secretKey []byte
)

// Add this struct for JWKS response
type JSONWebKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	K   string `json:"k"`
}

type JWKSResponse struct {
	Keys []JSONWebKey `json:"keys"`
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("JWKS endpoint called from: %s", r.RemoteAddr)
	log.Printf("Request headers: %+v", r.Header)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Encode the secret key in base64
	k := base64.RawURLEncoding.EncodeToString(secretKey)

	jwks := JWKSResponse{
		Keys: []JSONWebKey{
			{
				Kid: "key-1",
				Kty: "oct",
				Alg: "HS256",
				Use: "sig",
				K:   k,
			},
		},
	}

	log.Printf("Returning JWKS response: %+v", jwks)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("Error encoding JWKS response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func main() {
	// Initialize secret key
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your-256-bit-secret" // Default secret for development
	}
	log.Printf("JWT_SECRET: %s", secret)
	secretKey = []byte(secret)

	// API endpoints
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting JWT auth server on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("authHandler called")

	if r.Method != http.MethodGet {
		log.Printf("authHandler: Unsupported method %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		log.Println("authHandler: Missing authorization header")
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	log.Printf("authHandler: Received token: %s", tokenString)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("authHandler: Unexpected signing method: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		log.Printf("authHandler: Invalid token - Error: %v", err)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("authHandler: Invalid token claims")
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	if claims["aud"] != "kafka-broker" {
		log.Printf("authHandler: Invalid audience claim: %v", claims["aud"])
		http.Error(w, "Invalid audience", http.StatusUnauthorized)
		return
	}

	if claims["iss"] != "kafka-auth" {
		log.Printf("authHandler: Invalid issuer claim: %v", claims["iss"])
		http.Error(w, "Invalid issuer", http.StatusUnauthorized)
		return
	}

	log.Printf("authHandler: Token claims: %v", claims)

	// Return JWT claims in response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(claims)
}
