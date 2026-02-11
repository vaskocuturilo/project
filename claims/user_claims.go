package claims

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	Name     string `json:"user_name"`
	Lastname string `json:"user_lastname"`
	Email    string `json:"user_email"`
	jwt.RegisteredClaims
	TokenType string
}
