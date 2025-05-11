package main

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

const googleDiscoveryURL = "https://accounts.google.com/.well-known/openid-configuration"

type Application struct {
	config Config
}

type Config struct {
	oauth OAuthConfig
	jwt   JWTConfig
}

type JWKSConfig struct {
	JWKS               *JWKS        // googleJWKS
	Issuer             string       // googleIssuer
	Lock               sync.RWMutex // googleJWKSLock
	Expiry             time.Time    // googleJWKSExpiry
	minRefreshInterval time.Time    // minRefreshInterval
}

type CustomClaims struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Picture string `json:"picture"`
	jwt.RegisteredClaims
}

type DiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type OAuthConfig struct {
	client_id        string
	client_token_uri string
	client_secret    string
	redirect_uri     string
	jwks             *JWKSConfig
}

type TokenConfig struct {
	secret     []byte
	expires_in uint64
}

type JWTConfig struct {
	access  TokenConfig
	refresh TokenConfig
}

type JWK struct {
	Kty string `json:"kty"` // Key Type (e.g., "RSA")
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Public Key Use (e.g., "sig" for signature)
	Alg string `json:"alg"` // Algorithm (e.g., "RS256")
	N   string `json:"n"`   // RSA Modulus (Base64URL encoded)
	E   string `json:"e"`   // RSA Exponent (Base64URL encoded)
}

// JWKS (JSON Web Key Set) structure.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWTTokenData struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"token"`
	TokenType   string `json:"token_type"`
	IdToken     string `json:"id_token"`
}

func main() {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	app := &Application{}
	app.init()

	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))

	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Backend server"))
	})

	r.Get("/token", app.provideToken)

	r.Post("/token/refresh", app.refreshToken)

	r.Get("/me", app.getUserDetails)

	http.ListenAndServe(":3000", r)
}

func (app *Application) index(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(app.config.oauth.client_id))
}

func (app *Application) provideToken(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	if len(code) < 1 {
		writeJSONError(w, http.StatusUnauthorized, "Forbidden")
		return
	}

	tokens, err := app.config.oauth.exchangeCodeToTokens(code)

	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	claims, err := app.verifyGoogleIDToken(context.Background(), tokens.IdToken)

	// TODO
	// 1. create local token creation

}

func (app *Application) refreshToken(w http.ResponseWriter, r *http.Request) {
	// 2. implement
}

func (app *Application) getUserDetails(w http.ResponseWriter, r *http.Request) {
	// 3. Parse access token and return claims
}

func (app *Application) init() {
	oauth := OAuthConfig{
		client_id:        os.Getenv("VITE_GOOGLE_CLIENT_ID"),
		client_token_uri: os.Getenv("GOOGLE_CLIENT_TOKEN_URI"),
		client_secret:    os.Getenv("GOOGLE_CLIENT_SECRET"),
		redirect_uri:     os.Getenv("VITE_GOOGLE_REDIRECT_URI"),
		jwks:             &JWKSConfig{},
	}

	jwt := JWTConfig{
		access: TokenConfig{
			secret:     []byte(os.Getenv("JWT_ACCESS_TOKEN_SECRET")),
			expires_in: GetEnvInt("JWT_ACCESS_TOKEN_EXPIRES_IN", 0),
		},
		refresh: TokenConfig{
			secret:     []byte(os.Getenv("JWT_REFRESH_TOKEN_SECRET")),
			expires_in: GetEnvInt("JWT_ACCESS_TOKEN_EXPIRES_IN", 0),
		},
	}

	app.config = Config{
		oauth: oauth,
		jwt:   jwt,
	}

	err := app.fetchAndCacheGoogleJWKS(context.Background())
	if err != nil {
		log.Fatalf("Failed to pre-fetch Google JWKS: %v", err)
	}
}

func GetEnvInt(key string, fallback uint64) uint64 {
	val, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	valAsInt, err := strconv.Atoi(val)
	if err != nil {
		return fallback
	}
	return uint64(valAsInt)
}

// fetchAndCacheGoogleJWKS fetches Google's OIDC discovery document to find the JWKS URI,
// then fetches and caches the JWKS and the issuer.
// This function is internally synchronized.
func (app *Application) fetchAndCacheGoogleJWKS(ctx context.Context) error {
	// Check if cache is still valid under a read lock first
	app.config.oauth.jwks.Lock.RLock()
	if app.config.oauth.jwks.JWKS != nil && app.config.oauth.jwks.Issuer != "" && time.Now().Before(app.config.oauth.jwks.Expiry) {
		app.config.oauth.jwks.Lock.RUnlock()
		return nil // Cache is fresh
	}
	app.config.oauth.jwks.Lock.RUnlock()

	// Acquire write lock for fetching and updating
	app.config.oauth.jwks.Lock.Lock()
	defer app.config.oauth.jwks.Lock.Unlock()

	// Double-check after acquiring write lock, in case another goroutine refreshed it
	if app.config.oauth.jwks.JWKS != nil && app.config.oauth.jwks.Issuer != "" && time.Now().Before(app.config.oauth.jwks.Expiry) {
		return nil
	}

	log.Println("Fetching Google OIDC discovery document...")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleDiscoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for discovery document: %w", err)
	}

	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch discovery document: status %s", resp.Status)
	}

	var discoveryDoc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&discoveryDoc); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if discoveryDoc.JWKSURI == "" {
		return fmt.Errorf("jwks_uri not found in discovery document")
	}
	if discoveryDoc.Issuer == "" {
		return fmt.Errorf("issuer not found in discovery document")
	}

	log.Printf("Fetching Google JWKS from: %s", discoveryDoc.JWKSURI)
	jwksReq, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryDoc.JWKSURI, nil)
	if err != nil {
		return fmt.Errorf("failed to create request for JWKS: %w", err)
	}

	jwksResp, err := client.Do(jwksReq)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer jwksResp.Body.Close()

	if jwksResp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch JWKS: status %s", jwksResp.Status)
	}

	var jwks JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Update global cache
	app.config.oauth.jwks.JWKS = &jwks
	app.config.oauth.jwks.Issuer = discoveryDoc.Issuer
	app.config.oauth.jwks.Expiry = time.Now().Add(1 * time.Hour)
	log.Printf("Successfully fetched and cached Google JWKS. Issuer: %s. Next refresh after: %s", app.config.oauth.jwks.Issuer, app.config.oauth.jwks.Expiry.Format(time.RFC3339))
	return nil
}

// getKey is the jwt.Keyfunc used by jwt.ParseWithClaims.
// It retrieves the correct RSA public key from the cached Google JWKS based on the token's "kid" header.
func (app *Application) getKey(token *jwt.Token) (interface{}, error) {
	var currentJWKS *JWKS // Local snapshot of JWKS

	// Check cache status and potentially trigger a refresh
	app.config.oauth.jwks.Lock.RLock()
	if app.config.oauth.jwks.JWKS == nil || time.Now().After(app.config.oauth.jwks.Expiry) {
		app.config.oauth.jwks.Lock.RUnlock() // Release read lock before calling fetch

		// Cache is stale or empty, attempt to refresh it.
		// fetchAndCacheGoogleJWKS is internally synchronized.
		// Use a short timeout for this on-demand fetch.
		fetchCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if err := app.fetchAndCacheGoogleJWKS(fetchCtx); err != nil {
			return nil, fmt.Errorf("JWKS refresh failed during key retrieval: %w", err)
		}

		app.config.oauth.jwks.Lock.RLock() // Re-acquire read lock to get the (potentially) new JWKS
		currentJWKS = app.config.oauth.jwks.JWKS
		app.config.oauth.jwks.Lock.RUnlock()
	} else {
		// Cache is fresh, use it
		currentJWKS = app.config.oauth.jwks.JWKS
		app.config.oauth.jwks.Lock.RUnlock()
	}

	if currentJWKS == nil {
		return nil, fmt.Errorf("Google JWKS not available after checking cache and potential refresh")
	}

	// Get Key ID (kid) from token header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("token header missing 'kid' (Key ID)")
	}

	// Find the key with matching "kid"
	for _, key := range currentJWKS.Keys {
		if key.Kid == kid {
			// We expect RSA keys for Google OIDC
			if key.Kty == "RSA" && (key.Use == "sig" || key.Use == "") { // "use" can be "sig" or empty for signing keys
				// Decode Base64URL encoded Modulus (N)
				nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return nil, fmt.Errorf("failed to decode RSA modulus 'n' for kid %s: %w", kid, err)
				}
				// Decode Base64URL encoded Exponent (E)
				eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					return nil, fmt.Errorf("failed to decode RSA exponent 'e' for kid %s: %w", kid, err)
				}

				// Create rsa.PublicKey
				// The exponent 'E' is a base64url encoded big-endian unsigned integer.
				// It's typically small (e.g., 65537).
				pubKey := &rsa.PublicKey{
					N: new(big.Int).SetBytes(nBytes),
					E: int(new(big.Int).SetBytes(eBytes).Int64()),
				}
				return pubKey, nil
			}
			return nil, fmt.Errorf("key with kid '%s' found, but is not a usable RSA signing key (kty: %s, use: %s)", kid, key.Kty, key.Use)
		}
	}

	return nil, fmt.Errorf("unable to find public key for kid: '%s' in %d available keys", kid, len(currentJWKS.Keys))
}

// verifyGoogleIDToken verifies the given idTokenString against Google's public keys
// and parses it into CustomClaims.
// clientID is YOUR application's client ID (the audience).
func (app *Application) verifyGoogleIDToken(ctx context.Context, idTokenString string) (*CustomClaims, error) {
	// Ensure JWKS and issuer are loaded/fresh. This also populates `googleIssuer`.
	if err := app.fetchAndCacheGoogleJWKS(ctx); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch/cache failed: %w", err)
	}

	app.config.oauth.jwks.Lock.RLock()
	currentGoogleIssuer := app.config.oauth.jwks.Issuer // Get the issuer confirmed by discovery
	app.config.oauth.jwks.Lock.RUnlock()

	if currentGoogleIssuer == "" {
		return nil, fmt.Errorf("google issuer not configured; JWKS fetch might have failed to set it")
	}

	claims := &CustomClaims{}
	token, err := jwt.ParseWithClaims(idTokenString, claims, app.getKey,
		jwt.WithIssuer(currentGoogleIssuer),          // Verify the 'iss' claim
		jwt.WithAudience(app.config.oauth.client_id), // Verify the 'aud' claim
		jwt.WithLeeway(1*time.Minute),                // Allow 1 min clock skew for 'exp', 'nbf', 'iat'
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		// This case should ideally be caught by the specific errors above
		return nil, fmt.Errorf("token is invalid for an unspecified reason")
	}

	return claims, nil
}

func writeJSON(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

func readJSON(w http.ResponseWriter, r *http.Request, data any) error {
	maxBytes := 1_048_578 // accepts max 1MB of body
	r.Body = http.MaxBytesReader(w, r.Body, int64(maxBytes))

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	return decoder.Decode(data)
}

func writeJSONError(w http.ResponseWriter, status int, message string) error {
	type envelope struct {
		Error string `json:"error"`
	}
	return writeJSON(w, status, &envelope{Error: message})
}

func (oauth *OAuthConfig) exchangeCodeToTokens(code string) (*JWTTokenData, error) {
	// oauth.client_token_uri
	formData := url.Values{}
	formData.Set("code", code)
	formData.Set("client_id", oauth.client_id)
	formData.Set("client_secret", oauth.client_secret)
	formData.Set("redirect_uri", oauth.redirect_uri)
	formData.Set("grant_type", "authorization_code")

	encodedFormData := formData.Encode()

	req, err := http.NewRequest("POST", oauth.client_token_uri, strings.NewReader(encodedFormData))
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-HTTP-Client/1.0")
	client := &http.Client{
		Timeout: 10 * time.Second, // Set a timeout
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated { // Adjust accepted statuses as needed
		log.Printf("Received non-OK HTTP status: %d", resp.StatusCode)
		log.Printf("Response Body (raw): %s\n", string(bodyBytes))
		// You might want to return or handle this error more gracefully
		return nil, errors.New(fmt.Sprintf("Received non-OK HTTP status: %d", resp.StatusCode))
	}

	// log.Printf("Response Body (raw): %s\n", string(bodyBytes))

	tokens := JWTTokenData{}
	json.Unmarshal(bodyBytes, &tokens)

	return &tokens, nil
}
