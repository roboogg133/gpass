package crypt

import (
	"crypto/rand"
	"fmt"
	"io"
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
	f, err := os.OpenFile(filepath.Join(homeDir, config.TestFileName), os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return nil, nil, err
	}

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}

	fnonce, err := os.OpenFile(filepath.Join(homeDir, config.RootDirName, fmt.Sprintf("%s.nonce", config.TestFileName)), os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := io.ReadAll(fnonce)
	if err != nil {
		return nil, nil, err
	}

	return content, nonce, nil
}
