package token

import (
	"project1/auth"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var secret = []byte("b5bfec4b39eb6e579f4c3ba0e4a82f880e0fe0428719c54ad14b386930374789")

const issuer = "example.com"

func CreateAccessToken(u auth.User) (string, error) {
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
