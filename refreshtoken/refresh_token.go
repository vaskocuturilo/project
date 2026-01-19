package refreshtoken

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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

type request struct {
	RefreshToken string `json:"refresh_token"`
}

var req request

var ErrInvalidToken = errors.New("invalid token")

var (
	mx sync.RWMutex

	refreshTokens = make(map[string]struct{})
)

func Refresh(writer http.ResponseWriter, request *http.Request) {
	if err := json.NewDecoder(request.Body).Decode(&request); err != nil || req.RefreshToken == "" {
		http.Error(writer, "Invalid request body", http.StatusBadRequest)
		return
	}

	refreshToken, err := verifyRefreshToken(req.RefreshToken)

	if err != nil {
		http.Error(writer, "Bad refresh token", http.StatusBadRequest)
		return
	}

	newAccess, err := token.CreateAccessToken(refreshToken)
	if err != nil {
		http.Error(writer, "Error creating access token", http.StatusInternalServerError)
		return
	}

	newRefresh, err := createRefreshToken(refreshToken)
	if err != nil {
		http.Error(writer, "Error creating refresh token", http.StatusInternalServerError)
		return
	}

	type response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}

	writer.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(writer).Encode(response{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})
	if err != nil {
		return
	}
}

func createRefreshToken(u users.User) (string, error) {
	issuer := config.GetIssuer()

	secret := config.JWTSecret()

	tokenID := uuid.New().String()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":  issuer,
		"sub":  u.Name,
		"iat":  now.Unix(),
		"exp":  now.Add(7 * 24 * time.Hour).Unix(),
		"jti":  tokenID,
		"type": "refresh",
	}

	withClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := withClaims.SignedString(secret)
	if err != nil {
		return "", err
	}

	mx.Lock()
	refreshTokens[tokenID] = struct{}{}
	mx.Unlock()

	return signed, nil
}

func verifyRefreshToken(refreshToken string) (users.User, error) {
	issuer := config.GetIssuer()

	parse, err := jwt.Parse(refreshToken, utils.KeyFunc(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return users.User{}, fmt.Errorf("parse parse failed: %w", err)
	}

	if !parse.Valid {
		return users.User{}, ErrInvalidToken
	}

	claims, ok := parse.Claims.(jwt.MapClaims)
	if !ok || claims["type"] != "refresh" {
		return users.User{}, ErrInvalidToken
	}

	tokenID, ok := claims["jti"].(string)
	if !ok {
		return users.User{}, ErrInvalidToken
	}

	email, ok := claims["sub"].(string)
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
