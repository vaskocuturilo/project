package refreshtoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"project1/claims"
	"project1/internal/config"
	"project1/token"
	"project1/users"
	"project1/utils"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

var ErrInvalidToken = errors.New("invalid token")

var (
	mx sync.RWMutex

	refreshTokens = make(map[string]struct{})
)

func Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

	var req refreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		http.Error(w, "Invalid r body", http.StatusBadRequest)
		return
	}

	u, err := verifyRefreshToken(req.RefreshToken)

	if err != nil {
		http.Error(w, "Bad refresh token", http.StatusBadRequest)
		return
	}

	newAccess, err := token.CreateAccessToken(u)
	if err != nil {
		http.Error(w, "Error creating access token", http.StatusInternalServerError)
		return
	}

	newRefresh, err := createRefreshToken(u)
	if err != nil {
		http.Error(w, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(refreshResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
}

func createRefreshToken(u users.User) (string, error) {
	tokenID := uuid.New().String()

	userClaims := claims.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.GetIssuer(),
			Subject:   u.Email, // Use Email as the unique identifier
			ID:        tokenID, // This is the jti
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		TokenType: "refresh",
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims).
		SignedString(config.JWTSecret())

	if err != nil {
		return "", err
	}

	mx.Lock()
	refreshTokens[tokenID] = struct{}{}
	mx.Unlock()

	return signed, nil
}

func verifyRefreshToken(refreshToken string) (users.User, error) {
	c := &claims.UserClaims{}

	parseToken, err := jwt.ParseWithClaims(
		refreshToken,
		c,
		func(t *jwt.Token) (interface{}, error) {
			return utils.KeyFunc(), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil {
		return users.User{}, fmt.Errorf("parse parse failed: %w", err)
	}

	if !parseToken.Valid {
		return users.User{}, ErrInvalidToken
	}

	mapClaims, ok := parseToken.Claims.(jwt.MapClaims)
	if !ok || mapClaims["type"] != "refresh" {
		return users.User{}, ErrInvalidToken
	}

	tokenID, ok := mapClaims["jti"].(string)
	if !ok {
		return users.User{}, ErrInvalidToken
	}

	email, ok := mapClaims["sub"].(string)
	if !ok {
		return users.User{}, ErrInvalidToken
	}

	mx.RLock()
	_, exists := refreshTokens[tokenID]
	mx.RUnlock()

	if !exists {
		return users.User{}, ErrInvalidToken
	}

	mx.Lock()
	delete(refreshTokens, tokenID)
	mx.Unlock()

	usersDB := config.UserDB()

	idx := slices.IndexFunc(usersDB, func(u users.User) bool {
		return strings.EqualFold(email, u.Email)
	})
	if idx == -1 {
		return users.User{}, ErrInvalidToken
	}

	return usersDB[idx], nil
}
