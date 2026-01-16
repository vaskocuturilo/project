package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"project1/internal/config"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type contextKey string

var ErrInvalidToken = errors.New("invalid token")

const issuer = "example.com"

const userContextKey = contextKey("user")

type User struct {
	Name           string
	Lastname       string
	Email          string
	HashedPassword []byte
}

var usersDB = []User{
	{
		Name:           "John",
		Lastname:       "Doe",
		Email:          "john.doe@test.com",
		HashedPassword: hashPassword("john.doe.password"),
	},
	{
		Name:           "Jane",
		Lastname:       "Doe",
		Email:          "jane.doe@test.com",
		HashedPassword: hashPassword("jane.doe.password"),
	},
}

func hashPassword(password string) []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return hash
}

func checkPassword(hashedPassword []byte, password string) error {
	return bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
}

func AuthUser(email, password string) (User, error) {
	var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy-password"), bcrypt.DefaultCost)

	var ErrInvalidUserOrPassword = errors.New("invalid user or password")

	idx := slices.IndexFunc(usersDB, func(u User) bool {
		return strings.EqualFold(email, u.Email)
	})

	var hashToCheck []byte
	var userFound bool
	var usr User

	if idx == -1 {
		hashToCheck = dummyHash
		userFound = false
	} else {
		usr = usersDB[idx]
		hashToCheck = usr.HashedPassword
		userFound = true
	}

	err := checkPassword(hashToCheck, password)

	if !userFound || err != nil {
		return User{}, ErrInvalidUserOrPassword
	}

	return usr, nil
}

func GetUserFromContext(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userContextKey).(User)
	return u, ok
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")

		const bearerPrefix = "Bearer "
		if authHeader == "" || !strings.HasPrefix(authHeader, bearerPrefix) {
			http.Error(w, "Missing access token", http.StatusUnauthorized)
			return
		}

		rawToken := strings.TrimPrefix(authHeader, bearerPrefix)

		u, err := verifyAccessToken(rawToken)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		ctx := putUserToContext(r.Context(), u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func keyFunc() jwt.Keyfunc {
	secret := config.JWTSecret()

	return func(_ *jwt.Token) (interface{}, error) { return secret, nil }
}

func verifyAccessToken(accessToken string) (User, error) {
	parseToken, err := jwt.Parse(accessToken,
		keyFunc(),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return User{}, fmt.Errorf("parse parseToken failed: %w", err)
	}

	if !parseToken.Valid {
		return User{}, ErrInvalidToken
	}

	claims, ok := parseToken.Claims.(jwt.MapClaims)

	if !ok {
		return User{}, ErrInvalidToken
	}

	userLastname, _ := claims["user_lastname"].(string)
	userName, _ := claims["user_name"].(string)

	return User{
		Name:  userName,
		Email: userLastname,
	}, nil
}

func putUserToContext(ctx context.Context, u User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}
