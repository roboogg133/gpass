package crypt

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/roboogg133/gpass/config"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt returns ciphertext nonce and error
func Encrypt(key, plaintext []byte) ([]byte, []byte, error) {

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func GetTestFileAndNonce() ([]byte, []byte, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}

	content, err := os.ReadFile(filepath.Join(homeDir, config.RootDirName, config.TestFileName))
	if err != nil {
		return nil, nil, err
	}

	nonce, err := os.ReadFile(filepath.Join(homeDir, config.RootDirName, fmt.Sprintf("%s.nonce", config.TestFileName)))
	if err != nil {
		return nil, nil, err
	}

	return content, nonce, nil
}
