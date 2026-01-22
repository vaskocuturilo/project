package token

import (
	"project1/internal/config"
	"project1/users"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateAccessToken(t *testing.T) {
	mockUser := users.User{
		ID:       "f47ac10b-58cc-4372-a567",
		Name:     "John",
		Lastname: "Doe",
	}

	tokenString, err := CreateAccessToken(mockUser)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return config.JWTSecret(), nil
	})

	if err != nil || !token.Valid {
		t.Errorf("Token is not valid: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Could not parse claims")
	}

	if claims["sub"] != mockUser.ID {
		t.Errorf("Expected sub %s, got %s", mockUser.ID, claims["sub"])
	}
}
