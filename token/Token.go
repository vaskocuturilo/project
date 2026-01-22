package token

import (
	"fmt"
	"project1/internal/config"
	"project1/users"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func CreateAccessToken(u users.User) (string, error) {
	secret := config.JWTSecret()
	issuer := config.GetIssuer()

	tokenID := uuid.New().String()

	var claims = jwt.MapClaims{
		"iss":           issuer,
		"sub":           u.ID,
		"jti":           tokenID,
		"nbf":           time.Now().Unix(),
		"iat":           time.Now().Unix(),
		"exp":           time.Now().Add(config.AccessTokenDuration()).Unix(),
		"user_name":     u.Name,
		"user_lastname": u.Lastname,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(secret)

	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}

	return signedToken, err
}
