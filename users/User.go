package users

type User struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Lastname       string `json:"lastname"`
	Email          string `json:"email"`
	HashedPassword []byte `json:"hashed-password"`
}
