package rndm

import (
	"math/rand"
	"time"
)

var (
	chars = "1234567890QWERTYUIOPMLKJHGFDSAZXCVBNqwertyuiopmlkjhgfdsazxcvbn"
)

func Bytes(length int) []byte {
	rand.Seed(time.Now().UTC().UnixNano())
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return result
}

func String(length int) string {
	return string(Bytes(length))
}
