package token

import (
	"project1/auth"
	"project1/internal/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuer = "example.com"

func CreateAccessToken(u auth.User) (string, error) {
	secret := config.JWTSecret()

	var claims = jwt.MapClaims{
		"iss":           issuer,
		"sub":           u.Name,
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(15 * time.Minute).Unix(),
		"user_name":     u.Name,
		"user_lastname": u.Lastname,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secret)

	return signedToken, err
}
