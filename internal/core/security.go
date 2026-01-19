package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func EncryptToken(text string, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	// CBC mode IV must be block size
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// Padding is required for CBC
	plaintext = PKCS7Padding(plaintext, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(plaintext))
	mode.CryptBlocks(encrypted, plaintext)

	return base64.StdEncoding.EncodeToString(append(iv, encrypted...)), nil
}

func DecryptToken(encryptedText string, key string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	decrypted, err = PKCS7Unpadding(decrypted)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(ciphertext, padtext...)
}

func PKCS7Unpadding(plantText []byte) ([]byte, error) {
	length := len(plantText)
	if length == 0 {
		return nil, errors.New("invalid padding")
	}
	unpadding := int(plantText[length-1])
	if length < unpadding {
		return nil, errors.New("invalid padding")
	}
	return plantText[:(length - unpadding)], nil
}
