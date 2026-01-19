package users

type User struct {
	Name           string
	Lastname       string
	Email          string
	HashedPassword []byte
}
