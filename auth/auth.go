package auth

import (
	"errors"
	"slices"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

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
