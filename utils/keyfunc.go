package utils

import (
	"project1/internal/config"

	"github.com/golang-jwt/jwt/v5"
)

func KeyFunc() jwt.Keyfunc {
	secret := config.JWTSecret()

	return func(_ *jwt.Token) (interface{}, error) { return secret, nil }
}
