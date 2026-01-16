package config

var jwtSecretKey = []byte("b5bfec4b39eb6e579f4c3ba0e4a82f880e0fe0428719c54ad14b386930374789")

func JWTSecret() []byte {
	return jwtSecretKey
}
