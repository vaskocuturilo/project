package accesstoken

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"project1/internal/config"
	"project1/users"
	utils "project1/utils"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

var ErrInvalidToken = errors.New("invalid token")

const issuer = "example.com"

const userContextKey = contextKey("user")

func checkPassword(hashedPassword []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
}

func AuthUser(email, password string) (users.User, error) {
	var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

	var ErrInvalidUserOrPassword = errors.New("invalid user or password")

	userDB := config.UserDB()

	idx := slices.IndexFunc(userDB, func(u users.User) bool {
		return strings.EqualFold(email, u.Email)
	})

	var hashToCheck []byte
	var userFound bool
	var usr users.User

	if idx == -1 {
		hashToCheck = dummyHash
		userFound = false
	} else {
		usr = userDB[idx]
		hashToCheck = usr.HashedPassword
		userFound = true
	}

	err := checkPassword(hashToCheck, password)

	if !userFound || err != nil {
		return users.User{}, ErrInvalidUserOrPassword
	}

	return usr, nil
}

func GetUserFromContext(ctx context.Context) (users.User, bool) {
	u, ok := ctx.Value(userContextKey).(users.User)
	return u, ok
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		const bearerPrefix = "Bearer "
		if authHeader == "" || !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "Missing access token", http.StatusUnauthorized)
			return
		}

		rawToken := strings.TrimPrefix(authHeader, bearerPrefix)

		u, err := VerifyAccessToken(rawToken)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := putUserToContext(r.Context(), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func VerifyAccessToken(accessToken string) (users.User, error) {
	parseToken, err := jwt.Parse(accessToken,
		utils.KeyFunc(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return users.User{}, fmt.Errorf("parse parseToken failed: %w", err)
	}

	if !parseToken.Valid {
		return users.User{}, ErrInvalidToken
	}

	claims, ok := parseToken.Claims.(jwt.MapClaims)

	if !ok {
		return users.User{}, ErrInvalidToken
	}

	userLastname, _ := claims["user_lastname"].(string)
	userName, _ := claims["user_name"].(string)

	return users.User{
		Name:  userName,
		Email: userLastname,
	}, nil
}

func putUserToContext(ctx context.Context, u users.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}
