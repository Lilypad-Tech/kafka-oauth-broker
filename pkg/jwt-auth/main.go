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

// KeyConfig holds the configuration for a single JWT key
type KeyConfig struct {
	ID     string
	Secret []byte
}

// GlobalConfig holds all JWT key configurations
type GlobalConfig struct {
	Keys       map[string]KeyConfig
	ActiveKeys []string
	DefaultKey string
}

var (
	globalConfig GlobalConfig
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

func loadConfig() error {
	// Initialize the global config
	globalConfig = GlobalConfig{
		Keys: make(map[string]KeyConfig),
	}

	// Get active keys list
	activeKeysStr := os.Getenv("JWT_ACTIVE_KEYS")
	if activeKeysStr == "" {
		return fmt.Errorf("JWT_ACTIVE_KEYS environment variable is required")
	}
	globalConfig.ActiveKeys = strings.Split(activeKeysStr, ",")

	// Get default key
	globalConfig.DefaultKey = os.Getenv("JWT_DEFAULT_KEY")
	if globalConfig.DefaultKey == "" {
		return fmt.Errorf("JWT_DEFAULT_KEY environment variable is required")
	}

	// Load each active key's configuration
	for _, keyID := range globalConfig.ActiveKeys {
		// Adjust the prefix to remove extra _KEY_
		envPrefix := fmt.Sprintf("JWT_%s", strings.ReplaceAll(strings.ToUpper(keyID), "-", "_"))

		// Get the secret for the key
		secret := os.Getenv(envPrefix + "_SECRET")
		if secret == "" {
			return fmt.Errorf("missing secret for key %s", keyID)
		}

		// Add the key configuration
		config := KeyConfig{
			ID:     keyID,
			Secret: []byte(secret),
		}

		globalConfig.Keys[keyID] = config
	}

	return nil
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("JWKS endpoint called from: %s", r.RemoteAddr)

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create JWKS response with all active keys
	var jwksKeys []JSONWebKey
	for _, keyID := range globalConfig.ActiveKeys {
		if config, exists := globalConfig.Keys[keyID]; exists {
			k := base64.RawURLEncoding.EncodeToString(config.Secret)
			jwksKeys = append(jwksKeys, JSONWebKey{
				Kid: keyID,
				Kty: "oct",
				Alg: "HS256",
				Use: "sig",
				K:   k,
			})
		}
	}

	jwks := JWKSResponse{Keys: jwksKeys}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		log.Printf("Error encoding JWKS response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// API endpoints
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Starting JWT auth server on port %s with %d active keys",
		port, len(globalConfig.ActiveKeys))
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

	// Parse token without validating signature first to get the key ID
	parser := jwt.Parser{}
	token, _ := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	var keyID string
	if token != nil {
		if kid, ok := token.Header["kid"].(string); ok {
			keyID = kid
		}
	}

	// Get the correct key configuration
	keyConfig, exists := globalConfig.Keys[keyID]
	if !exists {
		log.Printf("authHandler: Unknown key ID: %s", keyID)
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Now parse and validate the token with the correct key
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return keyConfig.Secret, nil
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

	log.Printf("authHandler: Valid token with key %s, claims: %v", keyID, claims)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(claims)
}
