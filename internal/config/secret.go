package config

import (
	"project1/users"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var jwtSecretKey = []byte("b5bfec4b39eb6e579f4c3ba0e4a82f880e0fe0428719c54ad14b386930374789")

const issuer = "example.com"

func JWTSecret() []byte {
	return jwtSecretKey
}

func UserDB() []users.User {
	return usersDB
}

func GetIssuer() string {
	return issuer
}

func hashPassword(password string) []byte {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return hash
}

func AccessTokenDuration() time.Duration {
	return time.Duration(time.Now().Add(15 * time.Minute).Unix())
}

var usersDB = []users.User{
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
