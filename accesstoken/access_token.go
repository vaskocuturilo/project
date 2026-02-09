package accesstoken

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"project1/claims"
	"project1/internal/config"
	"project1/users"
	"project1/utils"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var dummyHash []byte

func init() {
	h, _ := bcrypt.GenerateFromPassword([]byte("static-dummy-password"), bcrypt.DefaultCost)
	dummyHash = h
}

type contextKey string

const userContextKey = contextKey("user")

func checkPassword(hashedPassword []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
}

func AuthUser(email, password string) (users.User, error) {
	var ErrInvalidUserOrPassword = errors.New("invalid user or password")

	userDB := config.UserDB()

	idx := slices.IndexFunc(userDB, func(u users.User) bool {
		return strings.EqualFold(email, u.Email)
	})

	var hashToCheck []byte
	var user users.User

	if idx == -1 {
		hashToCheck = dummyHash
	} else {
		user = userDB[idx]
		hashToCheck = user.HashedPassword
	}

	err := checkPassword(hashToCheck, password)

	if idx == -1 || err != nil {
		return users.User{}, ErrInvalidUserOrPassword
	}

	return user, nil
}

func GetUserFromContext(ctx context.Context) (users.User, bool) {
	u, ok := ctx.Value(userContextKey).(users.User)
	return u, ok
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		authHeader := r.Header.Get("Authorization")

		parts := strings.Fields(authHeader)

		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		u, err := VerifyAccessToken(parts[1])

		if err != nil {
			log.Printf("Token error: %v", err)
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := putUserToContext(r.Context(), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func VerifyAccessToken(accessToken string) (users.User, error) {
	c := &claims.UserClaims{}

	parseToken, err := jwt.ParseWithClaims(
		accessToken,
		c,
		func(t *jwt.Token) (interface{}, error) {
			return utils.KeyFunc(), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)

	if err != nil {
		return users.User{}, fmt.Errorf("token validation failed: %w", err)
	}

	if !parseToken.Valid {
		return users.User{}, errors.New("invalid token")
	}

	return users.User{
		Name:     c.Subject,
		Lastname: c.Lastname,
		Email:    c.Email,
	}, nil
}

func putUserToContext(ctx context.Context, u users.User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}
